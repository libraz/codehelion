//! WebAssembly implementation of the codehelion artifact backend boundary.
//!
//! Parsing validates a core module before retaining any facts from it. The
//! backend never instantiates the module: all output is derived from bytes.

use std::collections::{BTreeMap, BTreeSet};

use crate::support::format_support;
use crate::symbols::demangle;
use crate::{
    ArtifactBackend, ArtifactCall, ArtifactCapabilities, ArtifactDataSegment, ArtifactError,
    ArtifactFingerprint, ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactIr,
    ArtifactSection, ArtifactSourceMapping, ArtifactSymbol, NormalizedInstructions, UnresolvedCall,
};
use wasmparser::{
    ConstExpr, CustomSectionReader, ElementItems, Encoding, ExternalKind, KnownCustom, Name,
    Operator, Parser, Payload, TableInit, TypeRef, Validator, WasmFeatures,
};

/// Version of the immediate-free WebAssembly opcode representation.
pub const WASM_NORMALIZATION_VERSION: &str = "wasm-opcode-v1";

/// Version of the immediate-preserving WebAssembly body representation.
///
/// This is the level of detail between [`WASM_NORMALIZATION_VERSION`], which
/// keeps opcodes alone, and the raw body bytes, which pin every function index
/// a module happened to assign.
pub const WASM_BODY_VERSION: &str = "wasm-body-v1";

/// WebAssembly proposals this backend accepts, named rather than inherited.
///
/// The same set drives validation and every later decode, so a module is
/// refused for a property of its own -- truncation, an out-of-range index, a
/// type error -- and never because a dependency's default set does not name an
/// opcode family this backend's own decoder reads. Legacy exception handling
/// is one such family: toolchains still emit it, the decoder reads it, and
/// only the default feature set stood between such a module and a result.
/// Naming each proposal also keeps a dependency upgrade from silently widening
/// or narrowing what parses. Component-model proposals are absent because a
/// component is refused before any of them could apply.
fn accepted_features() -> WasmFeatures {
    WasmFeatures::MUTABLE_GLOBAL
        | WasmFeatures::SATURATING_FLOAT_TO_INT
        | WasmFeatures::SIGN_EXTENSION
        | WasmFeatures::REFERENCE_TYPES
        | WasmFeatures::MULTI_VALUE
        | WasmFeatures::BULK_MEMORY
        | WasmFeatures::SIMD
        | WasmFeatures::RELAXED_SIMD
        | WasmFeatures::THREADS
        | WasmFeatures::SHARED_EVERYTHING_THREADS
        | WasmFeatures::TAIL_CALL
        | WasmFeatures::FLOATS
        | WasmFeatures::MULTI_MEMORY
        | WasmFeatures::EXCEPTIONS
        | WasmFeatures::LEGACY_EXCEPTIONS
        | WasmFeatures::MEMORY64
        | WasmFeatures::EXTENDED_CONST
        | WasmFeatures::FUNCTION_REFERENCES
        | WasmFeatures::MEMORY_CONTROL
        | WasmFeatures::GC
        | WasmFeatures::GC_TYPES
        | WasmFeatures::CUSTOM_PAGE_SIZES
        | WasmFeatures::STACK_SWITCHING
        | WasmFeatures::WIDE_ARITHMETIC
}

/// Parser backend for a WebAssembly core module.
#[derive(Debug, Default, Clone, Copy)]
pub struct WasmBackend;

impl ArtifactBackend for WasmBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Wasm
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"\0asm")
    }

    #[allow(clippy::too_many_lines)] // Parsing follows Wasm's section stream in one pass.
    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
        if !self.detects(bytes) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::Wasm,
            });
        }
        if is_component(bytes) {
            return Err(ArtifactError::Unsupported {
                format: ArtifactFormat::Wasm,
            });
        }
        let features = accepted_features();
        Validator::new_with_features(features)
            .validate_all(bytes)
            .map_err(|error| malformed(error.to_string()))?;

        let mut state = ParseState::default();
        let mut ir = ArtifactIr::empty(ArtifactFormat::Wasm, bytes);
        let mut parser = Parser::new(0);
        parser.set_features(features);
        for payload in parser.parse_all(bytes) {
            let payload = payload.map_err(|error| malformed(error.to_string()))?;
            if let Some((id, range)) = payload.as_section() {
                ir.sections.push(ArtifactSection {
                    name: section_name(id).map(str::to_owned),
                    offset: range.start,
                    size: range.end.saturating_sub(range.start),
                    executable: id == 10,
                });
            }
            match payload {
                Payload::Version { encoding, .. } if encoding != Encoding::Module => {
                    return Err(ArtifactError::Unsupported {
                        format: ArtifactFormat::Wasm,
                    });
                }
                Payload::ImportSection(reader) => {
                    for import in reader.into_imports() {
                        let import = import.map_err(|error| malformed(error.to_string()))?;
                        ir.imports.push(ArtifactImport {
                            module: Some(import.module.to_owned()),
                            name: Some(import.name.to_owned()),
                            kind: import_kind(&import.ty),
                        });
                        if let TypeRef::Func(type_index) | TypeRef::FuncExact(type_index) =
                            import.ty
                        {
                            state
                                .function_types
                                .insert(state.imported_functions, type_index);
                            state.imported_functions += 1;
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for type_index in reader {
                        state
                            .defined_function_types
                            .push(type_index.map_err(|error| malformed(error.to_string()))?);
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(|error| malformed(error.to_string()))?;
                        if export.kind == ExternalKind::Func {
                            state
                                .export_names
                                .insert(export.index, export.name.to_owned());
                            state.exports.insert(export.index);
                        }
                    }
                }
                Payload::StartSection { func, .. } => {
                    state.start = Some(func);
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        let element = element.map_err(|error| malformed(error.to_string()))?;
                        if let ElementItems::Functions(functions) = element.items {
                            for function in functions {
                                state.element_functions.insert(
                                    function.map_err(|error| malformed(error.to_string()))?,
                                );
                            }
                        } else if let ElementItems::Expressions(_, expressions) = element.items {
                            for expression in expressions {
                                let expression =
                                    expression.map_err(|error| malformed(error.to_string()))?;
                                collect_function_references(
                                    &expression,
                                    &mut state.element_functions,
                                )?;
                            }
                        }
                    }
                }
                Payload::GlobalSection(reader) => {
                    for global in reader {
                        let global = global.map_err(|error| malformed(error.to_string()))?;
                        collect_function_references(
                            &global.init_expr,
                            &mut state.element_functions,
                        )?;
                    }
                }
                Payload::TableSection(reader) => {
                    for table in reader {
                        let table = table.map_err(|error| malformed(error.to_string()))?;
                        if let TableInit::Expr(expression) = table.init {
                            collect_function_references(&expression, &mut state.element_functions)?;
                        }
                    }
                }
                Payload::CustomSection(section) => {
                    read_custom_section(&section, &mut state, &mut ir);
                }
                Payload::CodeSectionEntry(body) => {
                    let defined = u32::try_from(state.functions.len())
                        .map_err(|_| malformed("too many defined functions".to_owned()))?;
                    let index = state
                        .imported_functions
                        .checked_add(defined)
                        .ok_or_else(|| malformed("too many functions".to_owned()))?;
                    let type_index = *state
                        .defined_function_types
                        .get(defined as usize)
                        .ok_or_else(|| malformed("function type is missing".to_owned()))?;
                    state.function_types.insert(index, type_index);
                    let mut function = parse_function(index, &body, bytes)?;
                    // A body that materialises a function reference hands out a
                    // callable the parser cannot follow, so its target joins the
                    // conservative roots exactly as a table element does.
                    state.element_functions.append(&mut function.references);
                    state.functions.push(function);
                }
                Payload::DataSection(reader) => {
                    for data in reader {
                        let data = data.map_err(|error| malformed(error.to_string()))?;
                        // The segment range opens at its flags and offset
                        // expression. An offset that reported those would not
                        // address the bytes beside it, so derive the payload
                        // start from the end of the range instead.
                        let payload_bytes = u64::try_from(data.data.len())
                            .map_err(|_| malformed("data segment is too large".to_owned()))?;
                        let offset =
                            data.range.end.checked_sub(payload_bytes).ok_or_else(|| {
                                malformed("data segment runs past its range".to_owned())
                            })?;
                        ir.data_segments.push(ArtifactDataSegment {
                            fingerprint: ArtifactFingerprint::from_content("wasm-data", data.data),
                            section: Some(11),
                            offset,
                            bytes: data.data.to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }

        let mut by_index = BTreeMap::new();
        for function in &mut state.functions {
            let name = resolved_name(&state.names, &state.export_names, function.index)
                .map(|name| demangle(name));
            let normalized = NormalizedInstructions {
                version: std::mem::take(&mut function.normalized.version),
                bytes: std::mem::take(&mut function.normalized.bytes),
            };
            let body = std::mem::take(&mut function.body);
            let fingerprint = symbol_fingerprint(name.as_deref(), &normalized.bytes);
            by_index.insert(function.index, fingerprint);
            ir.symbols.push(ArtifactSymbol {
                fingerprint,
                name,
                exported: state.exports.contains(&function.index),
                section: Some(10),
                offset: function.offset,
                size: function.code.len() as u64,
                size_inferred: false,
                code: std::mem::take(&mut function.code),
                normalized: Some(normalized),
                body_fingerprint: Some(body_fingerprint(&body)),
                inline_stack: Vec::new(),
            });
        }
        if let Some(start) = state.start.and_then(|index| by_index.get(&index)) {
            ir.entry_points.push(*start);
        }
        ir.indirect_references.extend(
            state
                .indirect_root_indices()
                .iter()
                .filter_map(|index| by_index.get(index))
                .copied(),
        );
        for function in &state.functions {
            let caller = by_index[&function.index];
            for call in &function.calls {
                let (target, unresolved) = match call {
                    PendingCall::Direct(index) => match by_index.get(index) {
                        Some(target) => (Some(*target), None),
                        None if *index < state.imported_functions => {
                            (None, Some(UnresolvedCall::ExternalImport))
                        }
                        None => (None, Some(UnresolvedCall::MissingRelocation)),
                    },
                    PendingCall::Indirect { .. } | PendingCall::Untyped => {
                        (None, Some(UnresolvedCall::IndirectTable))
                    }
                };
                ir.calls.push(ArtifactCall {
                    caller,
                    target,
                    unresolved,
                });
            }
        }
        let unreadable = ir.capabilities.debug_info_unreadable;
        ir.capabilities = self.capabilities();
        ir.capabilities.source_mapping = !ir.source_mappings.is_empty();
        ir.capabilities.debug_info_unreadable = unreadable;
        Ok(ir)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        format_support(ArtifactFormat::Wasm).capabilities
    }
}

/// Read a custom section for the facts this backend keeps, degrading rather
/// than failing when its bytes do not decode.
///
/// A custom section carries no fact a core module depends on, so a post-link
/// tool that leaves a broken `name` section behind must not cost the caller
/// the code, symbol, call-graph and data results the module itself still
/// supports. Whatever decoded before the failure is kept -- that prefix is a
/// function of the input alone, so two runs over the same bytes agree -- and
/// the loss is recorded as unreadable debug information rather than passed off
/// as an absence.
fn read_custom_section(
    section: &CustomSectionReader<'_>,
    state: &mut ParseState,
    ir: &mut ArtifactIr,
) {
    if section.name() == "sourceMappingURL" {
        match std::str::from_utf8(section.data()) {
            Ok(uri) => ir.source_mappings.push(ArtifactSourceMapping {
                uri: uri.to_owned(),
            }),
            Err(_) => ir.capabilities.debug_info_unreadable = true,
        }
    }
    if let KnownCustom::Name(names) = section.as_known() {
        for name in names {
            match name {
                Ok(Name::Function(functions)) => {
                    for function in functions {
                        let Ok(function) = function else {
                            ir.capabilities.debug_info_unreadable = true;
                            return;
                        };
                        state.names.insert(function.index, function.name.to_owned());
                    }
                }
                Ok(_) => {}
                Err(_) => {
                    ir.capabilities.debug_info_unreadable = true;
                    return;
                }
            }
        }
    }
}

/// Whether the preamble declares the component layer rather than a module.
///
/// Both encodings open with the same magic, so the layer word after the
/// version decides. Answering before validation keeps the refusal about the
/// encoding this backend does not read, rather than about a proposal missing
/// from the accepted feature set.
fn is_component(bytes: &[u8]) -> bool {
    matches!(bytes.get(6..8), Some([0x01, 0x00]))
}

const fn import_kind(import: &TypeRef) -> ArtifactImportKind {
    match import {
        TypeRef::Func(_) | TypeRef::FuncExact(_) => ArtifactImportKind::Function,
        TypeRef::Table(_) => ArtifactImportKind::Table,
        TypeRef::Memory(_) => ArtifactImportKind::Memory,
        TypeRef::Global(_) => ArtifactImportKind::Global,
        TypeRef::Tag(_) => ArtifactImportKind::Tag,
    }
}

/// State gathered from sections whose ordering differs from the code section.
#[derive(Default)]
struct ParseState {
    imported_functions: u32,
    start: Option<u32>,
    element_functions: BTreeSet<u32>,
    function_types: BTreeMap<u32, u32>,
    defined_function_types: Vec<u32>,
    /// Names the `name` custom section gives function indices.
    names: BTreeMap<u32, String>,
    /// Names the export section gives function indices.
    ///
    /// These are held apart from the name section rather than written into one
    /// map, because the two sources reach a module in whatever order it stores
    /// its sections, and a name that depends on that order would make a
    /// symbol's identity depend on how the module was laid out.
    export_names: BTreeMap<u32, String>,
    exports: BTreeSet<u32>,
    functions: Vec<PendingFunction>,
}

/// Resolve the name of a function index once the whole module is read.
///
/// The `name` custom section states what the producer called a function, so it
/// wins. An export name only says how the module publishes an index, and is
/// the fallback for an index the name section does not cover. Neither source
/// overwrites the other, so the answer is a function of what the module
/// declares and not of the order its sections happen to arrive in.
fn resolved_name<'a>(
    names: &'a BTreeMap<u32, String>,
    export_names: &'a BTreeMap<u32, String>,
    index: u32,
) -> Option<&'a String> {
    names.get(&index).or_else(|| export_names.get(&index))
}

impl ParseState {
    /// Return table references narrowed by observed indirect-call types.
    ///
    /// If no indirect call was seen, or an index has no type evidence, every
    /// table element remains a root. That avoids falsely claiming dead code
    /// when an export or host call can dispatch through the table. A transfer
    /// recorded without a type is type evidence the parser does not have, so
    /// it suppresses narrowing rather than narrowing against a partial set.
    fn indirect_root_indices(&self) -> BTreeSet<u32> {
        let mut types = BTreeSet::new();
        for call in self
            .functions
            .iter()
            .flat_map(|function| function.calls.iter())
        {
            match call {
                PendingCall::Indirect { type_index } => {
                    types.insert(*type_index);
                }
                PendingCall::Untyped => return self.element_functions.clone(),
                PendingCall::Direct(_) => {}
            }
        }
        if types.is_empty() {
            return self.element_functions.clone();
        }
        let narrowed: BTreeSet<_> = self
            .element_functions
            .iter()
            .filter(|index| {
                self.function_types
                    .get(index)
                    .is_some_and(|ty| types.contains(ty))
            })
            .copied()
            .collect();
        if narrowed.is_empty() {
            self.element_functions.clone()
        } else {
            narrowed
        }
    }
}

/// One body before its source-level function name has necessarily been seen.
struct PendingFunction {
    index: u32,
    offset: u64,
    code: Vec<u8>,
    normalized: NormalizedInstructions,
    /// The body bytes with every function-index immediate left out.
    body: Vec<u8>,
    calls: Vec<PendingCall>,
    references: BTreeSet<u32>,
}

/// A call target represented by the temporary WebAssembly index space only.
enum PendingCall {
    Direct(u32),
    Indirect {
        type_index: u32,
    },
    /// A control transfer this parser recognised without classifying further.
    Untyped,
}

/// Whether `opcode` is one of the single-byte control-transfer instructions.
///
/// The call family occupies one contiguous range, so a transfer this parser
/// does not name individually is still recorded rather than dropped: an edge
/// that leaves no evidence in the IR is indistinguishable from a resolved one.
const fn transfers_control(opcode: u8) -> bool {
    // call, call_indirect, return_call, return_call_indirect, call_ref,
    // return_call_ref.
    matches!(opcode, 0x10..=0x15)
}

/// Record every function a constant initializer expression materialises.
///
/// A `ref.func` outside a table element still hands the host or the module a
/// callable reference, so its target is a conservative reachability root in
/// exactly the way a table element is.
fn collect_function_references(
    expression: &ConstExpr<'_>,
    roots: &mut BTreeSet<u32>,
) -> Result<(), ArtifactError> {
    for operator in expression.get_operators_reader() {
        if let Operator::RefFunc { function_index } =
            operator.map_err(|error| malformed(error.to_string()))?
        {
            roots.insert(function_index);
        }
    }
    Ok(())
}

fn parse_function(
    index: u32,
    body: &wasmparser::FunctionBody<'_>,
    bytes: &[u8],
) -> Result<PendingFunction, ArtifactError> {
    let body_range = body.range();
    let capacity = usize::try_from(body_range.end.saturating_sub(body_range.start)).unwrap_or(0);
    let mut normalized = Vec::with_capacity(capacity);
    // The local declarations open the body and name no function, so they are
    // carried into the immediate-preserving form exactly as they were read.
    let operand_start = usize::try_from(
        body.get_binary_reader_for_operators()
            .map_err(|error| malformed(error.to_string()))?
            .original_position(),
    )
    .map_err(|_| malformed("operator offset lies outside the input".to_owned()))?;
    let body_start = usize::try_from(body_range.start)
        .map_err(|_| malformed("function body lies outside the input".to_owned()))?;
    let body_end = usize::try_from(body_range.end)
        .map_err(|_| malformed("function body lies outside the input".to_owned()))?;
    let mut form = Vec::with_capacity(capacity);
    form.extend(span(bytes, body_start, operand_start)?);
    let mut calls = Vec::new();
    let mut references = BTreeSet::new();
    let operators = body
        .get_operators_reader()
        .map_err(|error| malformed(error.to_string()))?;
    let mut pending: Option<PendingOperand> = None;
    for operator in operators.into_iter_with_offsets() {
        let (operator, offset) = operator.map_err(|error| malformed(error.to_string()))?;
        let offset = usize::try_from(offset)
            .map_err(|_| malformed("operator offset lies outside the input".to_owned()))?;
        if let Some(previous) = pending.take() {
            append_operand(&mut form, bytes, previous, offset)?;
        }
        let opcode = append_opcode_key(&mut normalized, bytes, offset)?;
        pending = Some(PendingOperand {
            offset,
            renumbers: names_a_function(&operator),
        });
        match operator {
            Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
                calls.push(PendingCall::Direct(function_index));
            }
            // A `call_ref` dispatches through a value rather than a table, but
            // both reach only functions the module made referenceable, and both
            // are bounded by the same conservative root set.
            Operator::CallIndirect { type_index, .. }
            | Operator::ReturnCallIndirect { type_index, .. }
            | Operator::CallRef { type_index }
            | Operator::ReturnCallRef { type_index } => {
                calls.push(PendingCall::Indirect { type_index });
            }
            Operator::RefFunc { function_index } => {
                references.insert(function_index);
            }
            _ if transfers_control(opcode) => calls.push(PendingCall::Untyped),
            _ => {}
        }
    }
    if let Some(previous) = pending {
        append_operand(&mut form, bytes, previous, body_end)?;
    }
    Ok(PendingFunction {
        index,
        offset: body_range.start,
        code: body.as_bytes().to_vec(),
        normalized: NormalizedInstructions {
            version: WASM_NORMALIZATION_VERSION.to_owned(),
            bytes: normalized,
        },
        body: form,
        calls,
        references,
    })
}

/// One operator whose extent is known only once the next one is read.
#[derive(Debug, Clone, Copy)]
struct PendingOperand {
    /// Where this operator starts in the module bytes.
    offset: usize,
    /// Whether its immediate is a function index, which renumbers when a
    /// neighbouring function is inserted or removed.
    renumbers: bool,
}

/// Whether this operator's immediate is a function index.
///
/// These are the only immediates the immediate-preserving form drops. A body
/// that merely moved within its module rewrites them and nothing else, so
/// keeping them would report every caller of a shifted function as changed.
/// Every one of them is a single-byte opcode, which is what lets the opcode be
/// kept while the index is dropped.
const fn names_a_function(operator: &Operator<'_>) -> bool {
    matches!(
        operator,
        Operator::Call { .. } | Operator::ReturnCall { .. } | Operator::RefFunc { .. }
    )
}

/// Append one operator to the immediate-preserving form.
///
/// An operator that names a function contributes its opcode alone; every other
/// operator contributes the bytes it occupies, immediates included.
fn append_operand(
    form: &mut Vec<u8>,
    bytes: &[u8],
    operand: PendingOperand,
    end: usize,
) -> Result<(), ArtifactError> {
    let end = if operand.renumbers {
        operand.offset.saturating_add(1)
    } else {
        end
    };
    form.extend(span(bytes, operand.offset, end)?);
    Ok(())
}

/// Read one byte range that the input is required to contain.
fn span(bytes: &[u8], start: usize, end: usize) -> Result<&[u8], ArtifactError> {
    bytes
        .get(start..end)
        .ok_or_else(|| malformed("operator extent lies outside the input".to_owned()))
}

/// Encode an opcode without any of its value, index, or branch immediates, and
/// return the leading opcode byte.
///
/// WebAssembly's extended opcodes start with an escape byte and a LEB128
/// subopcode. Keeping that subopcode distinguishes operations while allowing
/// local indices, call targets, labels, and constants to normalize away.
fn append_opcode_key(
    normalized: &mut Vec<u8>,
    bytes: &[u8],
    offset: usize,
) -> Result<u8, ArtifactError> {
    let opcode = *bytes
        .get(offset)
        .ok_or_else(|| malformed("operator offset lies outside the input".to_owned()))?;
    if !matches!(opcode, 0xfb..=0xfe) {
        normalized.push(opcode);
        return Ok(opcode);
    }
    let (subopcode, _) = unsigned_leb(bytes, offset + 1)?;
    normalized.push(opcode);
    normalized.extend(subopcode.to_le_bytes());
    Ok(opcode)
}

/// Read one unsigned LEB128 value only to distinguish an extended opcode.
fn unsigned_leb(bytes: &[u8], start: usize) -> Result<(u32, usize), ArtifactError> {
    let mut value = 0_u32;
    for shift in 0..5 {
        let index = start + shift;
        let byte = *bytes
            .get(index)
            .ok_or_else(|| malformed("truncated extended opcode".to_owned()))?;
        value |= u32::from(byte & 0x7f) << (shift * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(malformed("extended opcode LEB128 is too long".to_owned()))
}

fn symbol_fingerprint(name: Option<&str>, normalized: &[u8]) -> ArtifactFingerprint {
    let mut bytes = Vec::new();
    // The section and normalization recipe belong to identity. Function
    // indices do not: they only route calls while this one parse is in memory.
    bytes.push(10);
    let name = name.unwrap_or("");
    bytes.extend((name.len() as u64).to_le_bytes());
    bytes.extend(name.as_bytes());
    bytes.extend((WASM_NORMALIZATION_VERSION.len() as u64).to_le_bytes());
    bytes.extend(WASM_NORMALIZATION_VERSION.as_bytes());
    bytes.extend(normalized);
    ArtifactFingerprint::from_content("wasm-symbol", &bytes)
}

/// Identity of one body's instruction bytes with their immediate values.
///
/// The name is deliberately absent: this answers whether two bodies hold the
/// same instructions, and the identity that pairs two symbols across a
/// comparison carries the name already. The recipe version belongs to it for
/// the same reason it belongs to [`symbol_fingerprint`] -- two forms produced
/// by different rules must not collide.
fn body_fingerprint(body: &[u8]) -> ArtifactFingerprint {
    let mut bytes = Vec::with_capacity(body.len() + WASM_BODY_VERSION.len() + 8);
    bytes.extend((WASM_BODY_VERSION.len() as u64).to_le_bytes());
    bytes.extend(WASM_BODY_VERSION.as_bytes());
    bytes.extend(body);
    ArtifactFingerprint::from_content("wasm-symbol-body", &bytes)
}

const fn section_name(id: u8) -> Option<&'static str> {
    match id {
        0 => Some("custom"),
        1 => Some("type"),
        2 => Some("import"),
        3 => Some("function"),
        4 => Some("table"),
        5 => Some("memory"),
        6 => Some("global"),
        7 => Some("export"),
        8 => Some("start"),
        9 => Some("element"),
        10 => Some("code"),
        11 => Some("data"),
        12 => Some("datacount"),
        13 => Some("tag"),
        _ => None,
    }
}

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::Wasm,
        message,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::metrics;
    use proptest::prelude::*;

    const MODULE: &[u8] = &[
        0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 7, 7, 1, 3, b'f', b'o',
        b'o', 0, 0, 10, 9, 2, 4, 0, 16, 1, 11, 2, 0, 11, 11, 6, 1, 1, 3, b'a', b'b', b'c', 0, 18,
        4, b'n', b'a', b'm', b'e', 1, 11, 2, 0, 3, b'f', b'o', b'o', 1, 3, b'b', b'a', b'r',
    ];

    #[test]
    fn parses_code_names_calls_and_data_without_executing_the_module() {
        let artifact = WasmBackend.parse(MODULE).expect("fixture parses");
        assert_eq!(artifact.format, ArtifactFormat::Wasm);
        assert!(artifact.capabilities.symbols);
        assert!(artifact.capabilities.call_graph);
        assert!(artifact.capabilities.data_segments);
        assert_eq!(artifact.symbols.len(), 2);
        assert_eq!(artifact.symbols[0].name.as_deref(), Some("foo"));
        assert_eq!(artifact.symbols[1].name.as_deref(), Some("bar"));
        assert!(artifact.symbols[0].exported);
        assert!(!artifact.symbols[1].exported);
        assert_eq!(artifact.symbols[0].code, vec![0, 16, 1, 11]);
        assert_eq!(
            artifact.symbols[0].normalized.as_ref().unwrap().bytes,
            vec![16, 11]
        );
        assert_eq!(artifact.calls.len(), 1);
        assert_eq!(artifact.calls[0].caller, artifact.symbols[0].fingerprint);
        assert_eq!(
            artifact.calls[0].target,
            Some(artifact.symbols[1].fingerprint)
        );
        assert_eq!(artifact.data_segments[0].bytes, b"abc");
        assert!(
            artifact
                .sections
                .iter()
                .any(|section| section.name.as_deref() == Some("code") && section.executable)
        );
    }

    #[test]
    fn malformed_or_other_inputs_return_errors_instead_of_panicking() {
        assert!(matches!(
            WasmBackend.parse(b"not wasm"),
            Err(ArtifactError::WrongFormat { .. })
        ));
        assert!(matches!(
            WasmBackend.parse(b"\0asm\x01\0\0\0\x0a"),
            Err(ArtifactError::Malformed { .. })
        ));
    }

    proptest! {
        #[test]
        fn arbitrary_prefixed_and_damaged_bytes_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..2048),
            position in any::<prop::sample::Index>(),
            mask in 1_u8..=u8::MAX,
            cut in any::<prop::sample::Index>(),
        ) {
            let fixture = MODULE.to_vec();
            let mut flipped = fixture.clone();
            let at = position.index(flipped.len());
            flipped[at] ^= mask;
            let truncated = fixture[..cut.index(fixture.len())].to_vec();
            let mut magic = b"\0asm\x01\0\0\0".to_vec();
            magic.extend(&bytes);
            for input in [&bytes, &flipped, &truncated, &magic] {
                if let Err(failure) = crate::check_parse_answers(&WasmBackend, input) {
                    return Err(TestCaseError::fail(failure));
                }
            }
        }
    }

    #[test]
    fn parsing_the_same_module_twice_is_deterministic() {
        assert_eq!(
            WasmBackend.parse(MODULE).expect("first fixture parses"),
            WasmBackend.parse(MODULE).expect("second fixture parses")
        );
    }

    #[test]
    fn normalization_keeps_extended_opcodes_and_drops_call_immediates() {
        let mut normalized = Vec::new();
        append_opcode_key(&mut normalized, &[0x10, 0x01], 0).unwrap();
        append_opcode_key(&mut normalized, &[0x10, 0x7f], 0).unwrap();
        assert_eq!(normalized, vec![0x10, 0x10]);

        let mut extended = Vec::new();
        append_opcode_key(&mut extended, &[0xfc, 0x83, 0x01], 0).unwrap();
        assert_eq!(extended, vec![0xfc, 131, 0, 0, 0]);
        assert!(
            append_opcode_key(&mut extended, &[0xfc, 0x80, 0x80, 0x80, 0x80, 0x80], 0,).is_err()
        );
    }

    #[test]
    fn wasm_names_use_the_same_demangling_as_other_artifact_backends() {
        assert_eq!(demangle("ordinary_name"), "ordinary_name");
        assert!(demangle("_Z3fooi").contains("foo"));
        assert!(demangle("_ZN4test3foo17h0123456789abcdefE").contains("test::foo"));
    }

    #[test]
    fn fixture_ir_snapshot_is_current() {
        let artifact = WasmBackend.parse(MODULE).expect("fixture parses");
        let rendered = serde_json::to_string_pretty(&artifact).expect("IR serializes");
        assert_eq!(
            rendered,
            include_str!("../tests/golden/module-ir-v1.json").trim_end()
        );
    }

    #[test]
    fn a_module_without_a_name_section_keeps_the_code_and_leaves_names_absent() {
        // The custom name section starts after the passive data segment.
        let artifact = WasmBackend
            .parse(&MODULE[..47])
            .expect("stripped fixture parses");
        assert_eq!(artifact.symbols.len(), 2);
        assert_eq!(artifact.symbols[0].name.as_deref(), Some("foo"));
        assert_eq!(artifact.symbols[1].name, None);
        assert_eq!(artifact.symbols[1].code, vec![0, 11]);
    }

    #[test]
    fn imports_and_source_mapping_urls_are_retained_without_fetching_them() {
        let imported_module = [
            0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 2, 7, 1, 1, b'm', 1, b'f', 0, 0,
        ];
        let imported = WasmBackend
            .parse(&imported_module)
            .expect("import fixture parses");
        assert_eq!(imported.imports.len(), 1);
        assert_eq!(imported.imports[0].module.as_deref(), Some("m"));
        assert_eq!(imported.imports[0].name.as_deref(), Some("f"));
        assert_eq!(imported.imports[0].kind, ArtifactImportKind::Function);

        let mut source_mapped = MODULE.to_vec();
        source_mapped.extend([0, 26, 16]);
        source_mapped.extend(b"sourceMappingURL");
        source_mapped.extend(b"maps.json");
        let source_mapped = WasmBackend
            .parse(&source_mapped)
            .expect("source-map fixture parses");
        assert!(source_mapped.capabilities.source_mapping);
        assert_eq!(source_mapped.source_mappings[0].uri, "maps.json");
    }

    #[test]
    fn a_start_function_is_an_entry_point_even_when_not_exported() {
        let module = [
            0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 2, 1, 0, 8, 1, 0, 10, 4, 1, 2, 0, 11,
        ];
        let artifact = WasmBackend.parse(&module).expect("start fixture parses");
        assert_eq!(artifact.entry_points, vec![artifact.symbols[0].fingerprint]);
        assert!(
            metrics::dead_code_candidates(&artifact)
                .expect("entry point establishes roots")
                .symbols
                .is_empty()
        );
    }

    #[test]
    fn element_table_references_are_conservative_reachability_roots() {
        let module = [
            0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 4, 4, 1, 112, 0, 1, 9,
            9, 1, 4, 65, 0, 11, 1, 210, 1, 11, 10, 10, 2, 2, 0, 11, 5, 0, 65, 0, 26, 11,
        ];
        let artifact = WasmBackend.parse(&module).expect("element fixture parses");
        assert_eq!(
            artifact.indirect_references,
            vec![artifact.symbols[1].fingerprint]
        );
        let dead = metrics::dead_code_candidates(&artifact).expect("table establishes roots");
        assert_eq!(dead.symbols, vec![artifact.symbols[0].fingerprint]);
        assert!(dead.definitive);
    }

    /// One empty function type, two defined functions, and an exported first
    /// function. `body` supplies each body including its local declarations,
    /// and `global_reference` adds a `funcref` global holding `ref.func` of
    /// that index, which is also what declares the index for `ref.func` in a
    /// body.
    fn two_function_module(bodies: [&[u8]; 2], global_reference: Option<u8>) -> Vec<u8> {
        let mut module = vec![
            0, 97, 115, 109, 1, 0, 0, 0, // magic and version
            1, 4, 1, 96, 0, 0, // one type: [] -> []
            3, 3, 2, 0, 0, // two functions of that type
        ];
        if let Some(index) = global_reference {
            // One immutable funcref global initialised to `ref.func index`.
            module.extend([6, 6, 1, 0x70, 0, 0xd2, index, 0x0b]);
        }
        // Export the first function as "run".
        module.extend([7, 7, 1, 3, b'r', b'u', b'n', 0, 0]);
        let mut code = vec![2];
        for body in bodies {
            code.push(u8::try_from(body.len()).expect("test body fits one byte"));
            code.extend(body);
        }
        module.push(10);
        module.push(u8::try_from(code.len()).expect("test code section fits one byte"));
        module.extend(code);
        module
    }

    /// A `call_ref` reaches a callee this parser cannot name, so it stays in
    /// the IR as an unresolved edge instead of being dropped, and the function
    /// the module made referenceable stays a reachability root.
    #[test]
    fn call_ref_records_an_unresolved_edge_and_keeps_its_callee_reachable() {
        let module = two_function_module(
            [
                // ref.func 1; call_ref 0; end
                &[0, 0xd2, 1, 0x14, 0, 0x0b],
                &[0, 0x0b],
            ],
            Some(1),
        );

        let artifact = WasmBackend.parse(&module).expect("call_ref fixture parses");

        assert_eq!(artifact.symbols.len(), 2);
        assert_eq!(artifact.calls.len(), 1, "{artifact:#?}");
        assert_eq!(artifact.calls[0].caller, artifact.symbols[0].fingerprint);
        assert_eq!(artifact.calls[0].target, None);
        assert_eq!(
            artifact.calls[0].unresolved,
            Some(UnresolvedCall::IndirectTable)
        );
        assert_eq!(
            artifact.indirect_references,
            vec![artifact.symbols[1].fingerprint]
        );

        let dead = metrics::dead_code_candidates(&artifact).expect("an export establishes roots");
        assert!(!dead.definitive);
        assert!(
            !dead.symbols.contains(&artifact.symbols[1].fingerprint),
            "{dead:#?}"
        );
    }

    /// A `ref.func` in a global initialiser materialises a callable the parser
    /// cannot follow, so its target is a root exactly as a table element is.
    #[test]
    fn a_global_function_reference_is_a_conservative_reachability_root() {
        let module = two_function_module([&[0, 0x0b], &[0, 1, 0x0b]], Some(1));

        let artifact = WasmBackend.parse(&module).expect("global fixture parses");

        assert_eq!(
            artifact.indirect_references,
            vec![artifact.symbols[1].fingerprint]
        );
        let dead = metrics::dead_code_candidates(&artifact).expect("an export establishes roots");
        assert!(dead.symbols.is_empty(), "{dead:#?}");
        assert!(dead.definitive);
    }

    /// Normalization drops every immediate, so an optimizing build that only
    /// rewrote a constant leaves the symbol identity alone. The body identity
    /// is what still separates the two, and it stays blind to the function
    /// index a call names, which renumbers for reasons the body did not cause.
    #[test]
    fn a_body_identity_follows_the_immediates_but_not_the_function_indices() {
        // i32.const 1000000; drop; end, then the same with a narrow constant.
        let wide =
            two_function_module([&[0, 0x41, 0xc0, 0x84, 0x3d, 0x1a, 0x0b], &[0, 0x0b]], None);
        let narrow = two_function_module([&[0, 0x41, 0x00, 0x1a, 0x0b], &[0, 0x0b]], None);
        // call 1; end, then a module whose callee sits at another index.
        let calls_one = two_function_module([&[0, 0x10, 1, 0x0b], &[0, 0x0b]], None);
        let calls_zero = two_function_module([&[0, 0x10, 0, 0x0b], &[0, 0x0b]], None);

        let parsed = |module: &[u8]| {
            let artifact = WasmBackend.parse(module).expect("fixture parses");
            let symbol = artifact.symbols[0].clone();
            (
                symbol.fingerprint,
                symbol.body_fingerprint.expect("wasm decodes operands"),
            )
        };
        let (wide_symbol, wide_body) = parsed(&wide);
        let (narrow_symbol, narrow_body) = parsed(&narrow);
        let (one_symbol, one_body) = parsed(&calls_one);
        let (zero_symbol, zero_body) = parsed(&calls_zero);

        assert_eq!(wide_symbol, narrow_symbol, "the opcodes did not change");
        assert_ne!(wide_body, narrow_body, "the constant did change");
        assert_eq!(one_symbol, zero_symbol);
        assert_eq!(
            one_body, zero_body,
            "a call target is an index, and an index is not the body"
        );
    }

    /// A module without that global is the same module minus one root, which
    /// is what makes the reference above the reason the callee stays live.
    #[test]
    fn a_function_no_reference_reaches_is_reported_as_dead() {
        let module = two_function_module([&[0, 0x0b], &[0, 1, 0x0b]], None);

        let artifact = WasmBackend.parse(&module).expect("fixture parses");

        assert!(artifact.indirect_references.is_empty());
        let dead = metrics::dead_code_candidates(&artifact).expect("an export establishes roots");
        assert_eq!(dead.symbols, vec![artifact.symbols[1].fingerprint]);
        assert!(dead.definitive);
    }

    /// A call to an import names a callee index below the imported-function
    /// count, which is a resolved non-edge in the local graph rather than a
    /// gap in it. Real modules all call imports, so treating it as a gap left
    /// these sizes structurally unreachable.
    #[test]
    fn calling_an_import_keeps_the_local_call_graph_complete() {
        let module = [
            0, 97, 115, 109, 1, 0, 0, 0, // magic and version
            1, 4, 1, 96, 0, 0, // one type: [] -> []
            2, 7, 1, 1, b'm', 1, b'f', 0, 0, // import "m" "f" as a function
            3, 2, 1, 0, // one defined function
            7, 7, 1, 3, b'r', b'u', b'n', 0, 1, // export it as "run"
            10, 6, 1, 4, 0, 0x10, 0, 0x0b, // its body: call 0; end
        ];

        let artifact = WasmBackend.parse(&module).expect("import fixture parses");

        assert_eq!(artifact.symbols.len(), 1);
        assert_eq!(
            artifact.calls[0].unresolved,
            Some(UnresolvedCall::ExternalImport)
        );
        let sizes = metrics::classify_sizes(&artifact);
        assert_eq!(sizes.retained_bytes, Some(artifact.symbols[0].size));
        assert_eq!(sizes.shared_dependency_bytes, Some(0));
        assert!(
            !sizes
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("retained and shared dependency sizes need")),
            "{:?}",
            sizes.assumptions
        );
        assert!(metrics::retained_sizes(&artifact).is_some());
        let dead = metrics::dead_code_candidates(&artifact).expect("an export establishes roots");
        assert!(dead.definitive, "{dead:#?}");
        assert!(dead.symbols.is_empty());
    }

    /// A transfer of control this parser does not name individually still has
    /// to leave evidence, and it withdraws the type narrowing it supplies no
    /// type for.
    #[test]
    fn an_unnamed_control_transfer_suppresses_table_root_narrowing() {
        assert!(transfers_control(0x10));
        assert!(transfers_control(0x15));
        assert!(!transfers_control(0x0f));
        assert!(!transfers_control(0x16));

        let state = ParseState {
            element_functions: BTreeSet::from([0, 1, 2]),
            function_types: BTreeMap::from([(0, 7), (1, 8), (2, 7)]),
            functions: vec![PendingFunction {
                index: 3,
                offset: 0,
                code: Vec::new(),
                normalized: NormalizedInstructions {
                    version: WASM_NORMALIZATION_VERSION.to_owned(),
                    bytes: Vec::new(),
                },
                body: Vec::new(),
                calls: vec![
                    PendingCall::Indirect { type_index: 7 },
                    PendingCall::Untyped,
                ],
                references: BTreeSet::new(),
            }],
            ..ParseState::default()
        };

        assert_eq!(state.indirect_root_indices(), BTreeSet::from([0, 1, 2]));
    }

    /// One section with a one-byte length, which every fixture here fits in.
    fn section(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut encoded = vec![
            id,
            u8::try_from(payload.len()).expect("fixture section is short"),
        ];
        encoded.extend(payload);
        encoded
    }

    fn module(sections: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = vec![0, 97, 115, 109, 1, 0, 0, 0];
        for encoded in sections {
            bytes.extend(encoded);
        }
        bytes
    }

    /// One type `[] -> []`, one function of it, and a body that just returns.
    fn one_function_sections() -> [Vec<u8>; 3] {
        [
            section(1, &[1, 0x60, 0, 0]),
            section(3, &[1, 0]),
            section(10, &[1, 2, 0, 0x0b]),
        ]
    }

    /// A `name` custom section naming function index 0 `foo`.
    fn name_section(entry_count: u8) -> Vec<u8> {
        let mut payload = vec![4, b'n', b'a', b'm', b'e'];
        let subsection = [entry_count, 0, 3, b'f', b'o', b'o'];
        payload.push(1);
        payload.push(u8::try_from(subsection.len()).expect("fixture subsection is short"));
        payload.extend(subsection);
        section(0, &payload)
    }

    /// A `sourceMappingURL` custom section carrying `data`.
    fn source_mapping_section(data: &[u8]) -> Vec<u8> {
        let mut payload = vec![16];
        payload.extend(b"sourceMappingURL");
        payload.extend(data);
        section(0, &payload)
    }

    /// A body a producer that predates the current exception handling emits.
    ///
    /// The opcodes are `try` with an empty block type, `catch_all`, the end of
    /// the handler, and the end of the function.
    #[test]
    fn a_module_using_legacy_exception_handling_is_parsed_rather_than_refused() {
        let legacy = module(&[
            section(1, &[1, 0x60, 0, 0]),
            section(3, &[1, 0]),
            section(7, &[1, 3, b'r', b'u', b'n', 0, 0]),
            section(10, &[1, 6, 0, 0x06, 0x40, 0x19, 0x0b, 0x0b]),
        ]);

        let artifact = WasmBackend
            .parse(&legacy)
            .expect("a module whose opcodes this decoder reads is accepted");

        assert_eq!(artifact.symbols.len(), 1, "{artifact:#?}");
        assert_eq!(artifact.symbols[0].name.as_deref(), Some("run"));
        assert_eq!(
            artifact.symbols[0].code,
            vec![0, 0x06, 0x40, 0x19, 0x0b, 0x0b]
        );
    }

    /// The accepted set is chosen here, not inherited, and one set drives both
    /// the acceptance decision and every later decode.
    #[test]
    fn the_accepted_feature_set_is_stated_rather_than_inherited() {
        let features = accepted_features();
        assert!(features.legacy_exceptions());
        assert!(features.exceptions());
        assert!(features.bulk_memory());
        assert!(features.gc());
        assert_ne!(
            features,
            WasmFeatures::default(),
            "the backend must not inherit the dependency's default set"
        );
        let mut parser = Parser::new(0);
        parser.set_features(features);
        assert_eq!(parser.features(), features);
    }

    /// A post-link tool that leaves a broken `name` section behind must not
    /// cost the caller everything the core module still supports.
    #[test]
    fn a_truncated_name_section_degrades_to_unreadable_debug_information() {
        let mut sections = one_function_sections().to_vec();
        // The subsection declares two names and supplies one.
        sections.push(name_section(2));
        let damaged = module(&sections);

        let artifact = WasmBackend
            .parse(&damaged)
            .expect("a core module with a broken custom section still parses");

        assert!(artifact.capabilities.debug_info_unreadable, "{artifact:#?}");
        assert_eq!(artifact.symbols.len(), 1);
        assert_eq!(artifact.symbols[0].code, vec![0, 0x0b]);
        // The prefix that decoded before the failure is a function of the
        // input alone, so a second parse agrees with the first.
        assert_eq!(WasmBackend.parse(&damaged).expect("second parse"), artifact);
    }

    /// The code, call graph, sections and data of a module do not depend on a
    /// custom section that failed to decode.
    #[test]
    fn a_broken_custom_section_leaves_the_core_module_facts_untouched() {
        let mut damaged_sections = one_function_sections().to_vec();
        let plain = WasmBackend
            .parse(&module(&damaged_sections))
            .expect("plain parses");

        damaged_sections.push(source_mapping_section(&[0xff, 0xfe]));
        let damaged = WasmBackend
            .parse(&module(&damaged_sections))
            .expect("a non-UTF-8 sourceMappingURL does not fail the module");

        assert!(damaged.capabilities.debug_info_unreadable);
        assert!(damaged.source_mappings.is_empty(), "{damaged:#?}");
        assert!(!damaged.capabilities.source_mapping);
        assert_eq!(
            damaged
                .symbols
                .iter()
                .map(|symbol| (symbol.name.clone(), symbol.code.clone()))
                .collect::<Vec<_>>(),
            plain
                .symbols
                .iter()
                .map(|symbol| (symbol.name.clone(), symbol.code.clone()))
                .collect::<Vec<_>>()
        );
        assert_eq!(damaged.calls, plain.calls);
        assert_eq!(damaged.data_segments, plain.data_segments);
    }

    /// A reported data-segment offset has to address the reported bytes, so
    /// that pasting it into a hex viewer lands on the payload.
    #[test]
    fn a_data_segment_offset_addresses_its_own_payload() {
        // An active segment with three bytes, then an empty passive one.
        let with_data = module(&[
            section(1, &[1, 0x60, 0, 0]),
            section(3, &[1, 0]),
            section(5, &[1, 0, 1]),
            section(10, &[1, 2, 0, 0x0b]),
            section(11, &[2, 0, 0x41, 0x00, 0x0b, 3, b'x', b'y', b'z', 1, 0]),
        ]);

        for input in [MODULE.to_vec(), with_data] {
            let artifact = WasmBackend.parse(&input).expect("data fixture parses");
            assert!(!artifact.data_segments.is_empty(), "{artifact:#?}");
            for segment in &artifact.data_segments {
                let start = usize::try_from(segment.offset).expect("offset fits");
                let end = start + segment.bytes.len();
                assert_eq!(
                    input.get(start..end),
                    Some(segment.bytes.as_slice()),
                    "segment at {start} does not address its own bytes"
                );
            }
        }
    }

    /// A symbol's name, and therefore its identity, is a function of what the
    /// module declares rather than of the order it stores its sections in.
    #[test]
    fn a_name_section_outranks_an_export_name_in_either_section_order() {
        let head = [section(1, &[1, 0x60, 0, 0]), section(3, &[1, 0])];
        let export = section(7, &[1, 3, b'z', b'z', b'z', 0, 0]);
        let code = section(10, &[1, 2, 0, 0x0b]);

        let name_last = module(&[
            head[0].clone(),
            head[1].clone(),
            export.clone(),
            code.clone(),
            name_section(1),
        ]);
        let name_first = module(&[
            head[0].clone(),
            name_section(1),
            head[1].clone(),
            export,
            code,
        ]);

        let last = WasmBackend.parse(&name_last).expect("name-last parses");
        let first = WasmBackend.parse(&name_first).expect("name-first parses");

        assert_eq!(last.symbols[0].name.as_deref(), Some("foo"));
        assert_eq!(first.symbols[0].name.as_deref(), Some("foo"));
        assert_eq!(last.symbols[0].fingerprint, first.symbols[0].fingerprint);
        assert!(last.symbols[0].exported && first.symbols[0].exported);
    }

    /// An export name still names an index the name section does not cover.
    #[test]
    fn an_export_name_is_the_fallback_for_an_unnamed_index() {
        let exported = module(&[
            section(1, &[1, 0x60, 0, 0]),
            section(3, &[1, 0]),
            section(7, &[1, 3, b'z', b'z', b'z', 0, 0]),
            section(10, &[1, 2, 0, 0x0b]),
        ]);

        let artifact = WasmBackend.parse(&exported).expect("export fixture parses");

        assert_eq!(artifact.symbols[0].name.as_deref(), Some("zzz"));
    }

    /// Sections a module may carry are named, so a size reader never meets a
    /// row of bytes with no name attached.
    #[test]
    fn data_count_and_tag_sections_are_named() {
        let tagged = module(&[
            section(1, &[1, 0x60, 0, 0]),
            section(3, &[1, 0]),
            section(13, &[1, 0, 0]),
            section(12, &[1]),
            section(10, &[1, 2, 0, 0x0b]),
            section(11, &[1, 1, 0]),
        ]);

        let artifact = WasmBackend.parse(&tagged).expect("tagged fixture parses");

        let named: Vec<_> = artifact
            .sections
            .iter()
            .map(|section| section.name.as_deref())
            .collect();
        assert!(named.contains(&Some("datacount")), "{named:?}");
        assert!(named.contains(&Some("tag")), "{named:?}");
        assert!(named.iter().all(Option::is_some), "{named:?}");
        assert_eq!(
            artifact
                .sections
                .iter()
                .filter(|section| section.executable)
                .map(|section| section.name.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("code")]
        );
        assert_eq!(section_name(14), None);
    }

    /// The component encoding shares the module's magic and is recognised, but
    /// no backend reads it, so the refusal says exactly that.
    #[test]
    fn a_component_is_refused_as_an_encoding_this_backend_does_not_parse() {
        let component = [0, 97, 115, 109, 0x0d, 0x00, 0x01, 0x00];

        assert!(WasmBackend.detects(&component));
        assert!(is_component(&component));
        assert!(!is_component(MODULE));
        assert_eq!(
            WasmBackend.parse(&component),
            Err(ArtifactError::Unsupported {
                format: ArtifactFormat::Wasm
            })
        );
        // And that refusal is an answer, not a failure to answer. Stated here
        // rather than left to the property test above, which only meets a
        // component when its generator happens to flip the layer byte.
        assert_eq!(crate::check_parse_answers(&WasmBackend, &component), Ok(()));
    }

    /// A recorded source-map URL is the only source correspondence a core
    /// module carries, and the declaration has to admit it.
    #[test]
    fn the_declaration_admits_the_source_mapping_a_parse_can_establish() {
        let declared = WasmBackend.capabilities();
        assert!(declared.source_mapping);
        assert!(!declared.debug_info_unreadable);

        let mut mapped = MODULE.to_vec();
        mapped.extend(source_mapping_section(b"maps.json"));
        let artifact = WasmBackend
            .parse(&mapped)
            .expect("source-map fixture parses");

        assert!(artifact.capabilities.source_mapping);
        assert!(declared.source_mapping || !artifact.capabilities.source_mapping);
    }

    #[test]
    fn indirect_call_types_narrow_table_roots_when_all_types_are_known() {
        let state = ParseState {
            element_functions: BTreeSet::from([0, 1, 2]),
            function_types: BTreeMap::from([(0, 7), (1, 8), (2, 7)]),
            functions: vec![PendingFunction {
                index: 3,
                offset: 0,
                code: Vec::new(),
                normalized: NormalizedInstructions {
                    version: WASM_NORMALIZATION_VERSION.to_owned(),
                    bytes: Vec::new(),
                },
                body: Vec::new(),
                calls: vec![PendingCall::Indirect { type_index: 7 }],
                references: BTreeSet::new(),
            }],
            ..ParseState::default()
        };

        assert_eq!(state.indirect_root_indices(), BTreeSet::from([0, 2]));
    }
}
