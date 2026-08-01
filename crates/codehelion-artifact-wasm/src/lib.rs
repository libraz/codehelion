//! WebAssembly implementation of the codehelion artifact backend boundary.
//!
//! Parsing validates a core module before retaining any facts from it. The
//! backend never instantiates the module: all output is derived from bytes.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_artifact::symbols::demangle;
use codehelion_artifact::{
    ArtifactBackend, ArtifactCall, ArtifactCapabilities, ArtifactDataSegment, ArtifactError,
    ArtifactFingerprint, ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactIr,
    ArtifactSection, ArtifactSourceMapping, ArtifactSymbol, NormalizedInstructions, UnresolvedCall,
};
use wasmparser::{
    ElementItems, Encoding, ExternalKind, KnownCustom, Name, Operator, Parser, Payload, TypeRef,
    Validator,
};

/// Version of the immediate-free WebAssembly opcode representation.
pub const WASM_NORMALIZATION_VERSION: &str = "wasm-opcode-v1";

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
        Validator::new()
            .validate_all(bytes)
            .map_err(|error| malformed(error.to_string()))?;

        let mut state = ParseState::default();
        let mut ir = ArtifactIr::empty(ArtifactFormat::Wasm, bytes);
        for payload in Parser::new(0).parse_all(bytes) {
            let payload = payload.map_err(|error| malformed(error.to_string()))?;
            if let Some((id, range)) = payload.as_section() {
                ir.sections.push(ArtifactSection {
                    name: section_name(id).map(str::to_owned),
                    offset: range.start as u64,
                    size: range.len() as u64,
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
                            state.names.insert(export.index, export.name.to_owned());
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
                                let operators = expression.get_operators_reader();
                                for operator in operators {
                                    if let Operator::RefFunc { function_index } =
                                        operator.map_err(|error| malformed(error.to_string()))?
                                    {
                                        state.element_functions.insert(function_index);
                                    }
                                }
                            }
                        }
                    }
                }
                Payload::CustomSection(section) => {
                    if section.name() == "sourceMappingURL" {
                        let uri = std::str::from_utf8(section.data())
                            .map_err(|_| malformed("sourceMappingURL is not UTF-8".to_owned()))?;
                        ir.source_mappings.push(ArtifactSourceMapping {
                            uri: uri.to_owned(),
                        });
                    }
                    if let KnownCustom::Name(names) = section.as_known() {
                        for name in names {
                            if let Name::Function(functions) =
                                name.map_err(|error| malformed(error.to_string()))?
                            {
                                for function in functions {
                                    let function =
                                        function.map_err(|error| malformed(error.to_string()))?;
                                    state.names.insert(function.index, function.name.to_owned());
                                }
                            }
                        }
                    }
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
                    state.functions.push(parse_function(index, &body, bytes)?);
                }
                Payload::DataSection(reader) => {
                    for data in reader {
                        let data = data.map_err(|error| malformed(error.to_string()))?;
                        ir.data_segments.push(ArtifactDataSegment {
                            fingerprint: ArtifactFingerprint::from_content("wasm-data", data.data),
                            section: Some(11),
                            offset: data.range.start as u64,
                            bytes: data.data.to_vec(),
                        });
                    }
                }
                _ => {}
            }
        }

        let mut by_index = BTreeMap::new();
        for function in &mut state.functions {
            let name = state.names.get(&function.index).map(|name| demangle(name));
            let normalized = NormalizedInstructions {
                version: std::mem::take(&mut function.normalized.version),
                bytes: std::mem::take(&mut function.normalized.bytes),
            };
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
                    PendingCall::Indirect { .. } => (None, Some(UnresolvedCall::IndirectTable)),
                };
                ir.calls.push(ArtifactCall {
                    caller,
                    target,
                    unresolved,
                });
            }
        }
        ir.capabilities = self.capabilities();
        ir.capabilities.source_mapping = !ir.source_mappings.is_empty();
        Ok(ir)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        ArtifactCapabilities {
            symbols: true,
            call_graph: true,
            source_mapping: false,
            relocations: false,
            data_segments: true,
        }
    }
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
    names: BTreeMap<u32, String>,
    exports: BTreeSet<u32>,
    functions: Vec<PendingFunction>,
}

impl ParseState {
    /// Return table references narrowed by observed indirect-call types.
    ///
    /// If no indirect call was seen, or an index has no type evidence, every
    /// table element remains a root. That avoids falsely claiming dead code
    /// when an export or host call can dispatch through the table.
    fn indirect_root_indices(&self) -> BTreeSet<u32> {
        let types: BTreeSet<_> = self
            .functions
            .iter()
            .flat_map(|function| function.calls.iter())
            .filter_map(|call| match call {
                PendingCall::Indirect { type_index } => Some(*type_index),
                PendingCall::Direct(_) => None,
            })
            .collect();
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
    calls: Vec<PendingCall>,
}

/// A call target represented by the temporary WebAssembly index space only.
enum PendingCall {
    Direct(u32),
    Indirect { type_index: u32 },
}

fn parse_function(
    index: u32,
    body: &wasmparser::FunctionBody<'_>,
    bytes: &[u8],
) -> Result<PendingFunction, ArtifactError> {
    let mut normalized = Vec::with_capacity(body.range().len());
    let mut calls = Vec::new();
    let operators = body
        .get_operators_reader()
        .map_err(|error| malformed(error.to_string()))?;
    for operator in operators.into_iter_with_offsets() {
        let (operator, offset) = operator.map_err(|error| malformed(error.to_string()))?;
        append_opcode_key(&mut normalized, bytes, offset)?;
        match operator {
            Operator::Call { function_index } | Operator::ReturnCall { function_index } => {
                calls.push(PendingCall::Direct(function_index));
            }
            Operator::CallIndirect { type_index, .. }
            | Operator::ReturnCallIndirect { type_index, .. } => {
                calls.push(PendingCall::Indirect { type_index });
            }
            _ => {}
        }
    }
    Ok(PendingFunction {
        index,
        offset: body.range().start as u64,
        code: body.as_bytes().to_vec(),
        normalized: NormalizedInstructions {
            version: WASM_NORMALIZATION_VERSION.to_owned(),
            bytes: normalized,
        },
        calls,
    })
}

/// Encode an opcode without any of its value, index, or branch immediates.
///
/// WebAssembly's extended opcodes start with an escape byte and a LEB128
/// subopcode. Keeping that subopcode distinguishes operations while allowing
/// local indices, call targets, labels, and constants to normalize away.
fn append_opcode_key(
    normalized: &mut Vec<u8>,
    bytes: &[u8],
    offset: usize,
) -> Result<(), ArtifactError> {
    let opcode = *bytes
        .get(offset)
        .ok_or_else(|| malformed("operator offset lies outside the input".to_owned()))?;
    if !matches!(opcode, 0xfb..=0xfe) {
        normalized.push(opcode);
        return Ok(());
    }
    let (subopcode, _) = unsigned_leb(bytes, offset + 1)?;
    normalized.push(opcode);
    normalized.extend(subopcode.to_le_bytes());
    Ok(())
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
    use codehelion_artifact::metrics;
    use proptest::prelude::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

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
        fn arbitrary_and_truncated_wasm_bytes_never_panic(
            bytes in prop::collection::vec(any::<u8>(), 0..2048),
        ) {
            let mut truncated = b"\0asm\x01\0\0\0".to_vec();
            truncated.extend(&bytes);
            for input in [&bytes, &truncated] {
                let result = catch_unwind(AssertUnwindSafe(|| WasmBackend.parse(input)));
                prop_assert!(result.is_ok());
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
                calls: vec![PendingCall::Indirect { type_index: 7 }],
            }],
            ..ParseState::default()
        };

        assert_eq!(state.indirect_root_indices(), BTreeSet::from([0, 2]));
    }
}
