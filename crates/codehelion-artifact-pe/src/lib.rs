//! PE and COFF implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the inspected artifact. PDB source locations are intentionally a
//! separate correlation input: this parser establishes only facts present in
//! the PE or COFF container itself.

use std::collections::BTreeSet;
use std::io::Cursor;

use codehelion_artifact::{
    ArtifactBackend, ArtifactCapabilities, ArtifactDataSegment, ArtifactError, ArtifactFingerprint,
    ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactIr, ArtifactRelocation,
    ArtifactSection, ArtifactSymbol, NormalizedInstructions,
};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolKind,
};
use pdb::{FallibleIterator, PDB};

/// Parser backend for PE images and COFF objects.
#[derive(Debug, Default, Clone, Copy)]
pub struct PeCoffBackend;

/// Version of the x86 instruction-shape normalization representation.
pub const PE_COFF_NORMALIZATION_VERSION: &str = "x86-operand-shape-v1";

impl ArtifactBackend for PeCoffBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::PeCoff
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        // `object` verifies the complete container. This inexpensive check is
        // only dispatch evidence, so either a COFF file header or PE DOS magic
        // is sufficient here.
        bytes.starts_with(b"MZ") || is_coff_machine(bytes)
    }

    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
        self.parse_with_pdb(bytes, None)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        ArtifactCapabilities {
            symbols: true,
            call_graph: false,
            source_mapping: false,
            relocations: true,
            data_segments: true,
        }
    }
}

impl PeCoffBackend {
    /// Parse a PE or COFF artifact with an optional, already-read PDB.
    ///
    /// A PDB is used only for a PE image that carries matching `CodeView` GUID
    /// and age metadata. COFF objects have no corresponding image identity, so
    /// a supplied PDB is rejected rather than guessed at.
    ///
    /// # Errors
    ///
    /// Returns an error when the input is another format, malformed, or the
    /// optional PDB does not match the PE image exactly enough to be evidence.
    pub fn parse_with_pdb(
        &self,
        bytes: &[u8],
        pdb_bytes: Option<&[u8]>,
    ) -> Result<ArtifactIr, ArtifactError> {
        let file = object::File::parse(bytes).map_err(|error| malformed(error.to_string()))?;
        if !matches!(
            file.format(),
            object::BinaryFormat::Coff | object::BinaryFormat::Pe
        ) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::PeCoff,
            });
        }
        let mut ir = ArtifactIr::empty(ArtifactFormat::PeCoff, bytes);
        collect_sections(&file, &mut ir)?;
        collect_imports(&file, &mut ir);
        let symbol_ranges = collect_symbols(&file, &mut ir)?;
        if let Some(pdb_bytes) = pdb_bytes {
            collect_pdb_frames(&file, pdb_bytes, &symbol_ranges, &mut ir)?;
        }
        ir.capabilities = ArtifactCapabilities {
            symbols: !ir.symbols.is_empty(),
            call_graph: false,
            source_mapping: !ir.source_mappings.is_empty(),
            relocations: !ir.relocations.is_empty(),
            data_segments: !ir.data_segments.is_empty(),
        };
        Ok(ir)
    }
}

/// One parser-local symbol address range used to join PDB RVAs to stable IDs.
#[derive(Debug, Clone, Copy)]
struct SymbolRange {
    fingerprint: ArtifactFingerprint,
    start: u64,
    end: u64,
}

fn is_coff_machine(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..2),
        Some([0x4c, 0x01] | [0x64, 0x86 | 0xaa] | [0xaa, 0x64])
    )
}

fn collect_sections(file: &object::File<'_>, ir: &mut ArtifactIr) -> Result<(), ArtifactError> {
    for section in file.sections() {
        let (offset, size) = section.file_range().unwrap_or((0, 0));
        ir.sections.push(ArtifactSection {
            name: section.name().ok().map(str::to_owned),
            offset,
            size,
            executable: section.kind() == SectionKind::Text,
        });
        if section.kind() == SectionKind::ReadOnlyData {
            let data = section
                .data()
                .map_err(|error| malformed(error.to_string()))?;
            if !data.is_empty() {
                ir.data_segments.push(ArtifactDataSegment {
                    fingerprint: data_fingerprint(section.name().ok(), data),
                    section: u32::try_from(section.index().0).ok(),
                    offset,
                    bytes: data.to_vec(),
                });
            }
        }
        for (relocation_offset, relocation) in section.relocations() {
            ir.relocations.push(ArtifactRelocation {
                section: u32::try_from(section.index().0).ok(),
                offset: offset.saturating_add(relocation_offset),
                kind: format!("{:?}", relocation.kind()),
                target: relocation_target_name(file, relocation.target()),
            });
        }
    }
    Ok(())
}

fn collect_imports(file: &object::File<'_>, ir: &mut ArtifactIr) {
    let mut names = BTreeSet::new();
    for symbol in file.symbols() {
        if symbol.kind() == SymbolKind::Text && symbol.is_undefined() {
            if let Some(name) = symbol
                .name()
                .ok()
                .filter(|name| !name.is_empty())
                .map(demangle)
            {
                names.insert(name);
            }
        }
    }
    ir.imports
        .extend(names.into_iter().map(|name| ArtifactImport {
            module: None,
            name: Some(name),
            kind: ArtifactImportKind::Function,
        }));
}

fn collect_symbols(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<Vec<SymbolRange>, ArtifactError> {
    let mut ranges = Vec::new();
    for section in file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
    {
        let section_index = section.index();
        let data = section
            .data()
            .map_err(|error| malformed(error.to_string()))?;
        let (section_offset, _) = section.file_range().unwrap_or((0, 0));
        let mut symbols: Vec<_> = file
            .symbols()
            .filter(|symbol| {
                symbol.section_index() == Some(section_index) && !symbol.is_undefined()
            })
            .collect();
        symbols.sort_by_key(ObjectSymbol::address);
        for (index, symbol) in symbols.iter().enumerate() {
            let Some(relative) = symbol.address().checked_sub(section.address()) else {
                continue;
            };
            let next = symbols.get(index + 1).map_or_else(
                || section.address().saturating_add(data.len() as u64),
                ObjectSymbol::address,
            );
            let size = if symbol.size() == 0 {
                next.saturating_sub(symbol.address())
            } else {
                symbol.size()
            };
            let Ok(start) = usize::try_from(relative) else {
                continue;
            };
            let Ok(size) = usize::try_from(size) else {
                continue;
            };
            let Some(code) = data.get(start..start.saturating_add(size)) else {
                continue;
            };
            if code.is_empty() {
                continue;
            }
            let name = symbol
                .name()
                .ok()
                .filter(|name| !name.is_empty())
                .map(demangle);
            let normalized = normalize_x86(code, file.architecture());
            let fingerprint = symbol_fingerprint(
                name.as_deref(),
                section.name().ok(),
                normalized.as_ref(),
                code,
            );
            ir.symbols.push(ArtifactSymbol {
                fingerprint,
                name,
                exported: symbol.is_global(),
                section: u32::try_from(section_index.0).ok(),
                offset: section_offset.saturating_add(relative),
                size: u64::try_from(size).unwrap_or(u64::MAX),
                size_inferred: symbol.size() == 0,
                code: code.to_vec(),
                normalized,
                inline_stack: Vec::new(),
            });
            ranges.push(SymbolRange {
                fingerprint,
                start: symbol.address(),
                end: symbol
                    .address()
                    .saturating_add(u64::try_from(size).unwrap_or(u64::MAX)),
            });
        }
    }
    Ok(ranges)
}

/// Attach PDB line records to symbol identities after checking `CodeView` identity.
///
/// PDB RVAs and image symbol addresses are used only during this join. The
/// stored graph keeps stable symbol fingerprints and source locations, never a
/// PE address, section number, or PDB stream index as identity.
#[allow(
    clippy::too_many_lines,
    reason = "the identity check, fallible PDB iteration, and stable-ID attachment form one safety boundary"
)]
fn collect_pdb_frames(
    file: &object::File<'_>,
    pdb_bytes: &[u8],
    symbol_ranges: &[SymbolRange],
    ir: &mut ArtifactIr,
) -> Result<(), ArtifactError> {
    if file.format() != object::BinaryFormat::Pe {
        return Err(malformed(
            "a PDB can only describe a PE image, not a COFF object".to_owned(),
        ));
    }
    let image_pdb = file
        .pdb_info()
        .map_err(|error| malformed(error.to_string()))?
        .ok_or_else(|| malformed("PE image has no CodeView PDB identity".to_owned()))?;
    let mut pdb =
        PDB::open(Cursor::new(pdb_bytes)).map_err(|error| malformed(error.to_string()))?;
    let pdb_info = pdb
        .pdb_information()
        .map_err(|error| malformed(error.to_string()))?;
    if !pdb_identity_matches(
        pdb_info.guid.to_bytes_le(),
        pdb_info.age,
        image_pdb.guid(),
        image_pdb.age(),
    ) {
        return Err(malformed(
            "PDB GUID or age does not match the PE image".to_owned(),
        ));
    }
    let address_map = pdb
        .address_map()
        .map_err(|error| malformed(error.to_string()))?;
    let string_table = pdb
        .string_table()
        .map_err(|error| malformed(error.to_string()))?;
    let debug_information = pdb
        .debug_information()
        .map_err(|error| malformed(error.to_string()))?;
    let mut modules = debug_information
        .modules()
        .map_err(|error| malformed(error.to_string()))?;
    let mut frames = Vec::new();
    while let Some(module) = modules
        .next()
        .map_err(|error| malformed(error.to_string()))?
    {
        let Some(module_info) = pdb
            .module_info(&module)
            .map_err(|error| malformed(error.to_string()))?
        else {
            continue;
        };
        let Ok(program) = module_info.line_program() else {
            continue;
        };
        let mut lines = program.lines();
        while let Some(line) = lines.next().map_err(|error| malformed(error.to_string()))? {
            let Some(rva) = line.offset.to_rva(&address_map) else {
                continue;
            };
            let Ok(file_info) = program.get_file_info(line.file_index) else {
                continue;
            };
            let Ok(source) = file_info.name.to_string_lossy(&string_table) else {
                continue;
            };
            frames.push((
                u64::from(rva.0),
                codehelion_artifact::ArtifactInlineFrame {
                    source: source.into_owned(),
                    line: Some(line.line_start),
                    column: line.column_start.filter(|column| *column != 0),
                },
            ));
        }
    }
    for range in symbol_ranges {
        let mut symbol_frames: Vec<_> = frames
            .iter()
            .filter(|(address, _)| range.start <= *address && *address < range.end)
            .map(|(_, frame)| frame.clone())
            .collect();
        symbol_frames.sort_by(|left, right| {
            (&left.source, left.line, left.column).cmp(&(&right.source, right.line, right.column))
        });
        symbol_frames.dedup();
        if symbol_frames.is_empty() {
            continue;
        }
        if let Some(symbol) = ir
            .symbols
            .iter_mut()
            .find(|symbol| symbol.fingerprint == range.fingerprint)
        {
            symbol.inline_stack = symbol_frames;
        }
    }
    ir.source_mappings = ir
        .symbols
        .iter()
        .flat_map(|symbol| symbol.inline_stack.iter().map(|frame| frame.source.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|uri| codehelion_artifact::ArtifactSourceMapping { uri })
        .collect();
    Ok(())
}

/// Determine whether a PDB identity can describe the PE image identity.
///
/// A linker can rewrite a PDB without relinking its PE image. Therefore the
/// matching GUID must be exact while the PDB age may be newer than the age
/// recorded in the PE image.
fn pdb_identity_matches(
    pdb_guid: [u8; 16],
    pdb_age: u32,
    image_guid: [u8; 16],
    image_age: u32,
) -> bool {
    pdb_guid == image_guid && pdb_age >= image_age
}

fn relocation_target_name(file: &object::File<'_>, target: RelocationTarget) -> Option<String> {
    let RelocationTarget::Symbol(index) = target else {
        return None;
    };
    file.symbol_by_index(index)
        .ok()
        .and_then(|symbol| symbol.name().ok())
        .filter(|name| !name.is_empty())
        .map(demangle)
}

fn demangle(name: &str) -> String {
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        return format!("{symbol:#}");
    }
    cpp_demangle::Symbol::new(name.as_bytes())
        .ok()
        .and_then(|symbol| symbol.demangle().ok())
        .unwrap_or_else(|| name.to_owned())
}

fn normalize_x86(code: &[u8], architecture: Architecture) -> Option<NormalizedInstructions> {
    let bitness = match architecture {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return None,
    };
    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut normalized = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        normalized.extend((instruction.code() as u32).to_le_bytes());
        normalized.push(u8::try_from(instruction.op_count()).ok()?);
        for operand in 0..instruction.op_count() {
            let kind = instruction.op_kind(operand);
            normalized.push(kind as u8);
            if kind == OpKind::Memory {
                normalized.push(instruction.memory_size() as u8);
                normalized.push(u8::try_from(instruction.memory_index_scale()).ok()?);
                normalized.push(u8::try_from(instruction.memory_displ_size()).ok()?);
            }
        }
    }
    Some(NormalizedInstructions {
        version: PE_COFF_NORMALIZATION_VERSION.to_owned(),
        bytes: normalized,
    })
}

fn symbol_fingerprint(
    name: Option<&str>,
    section: Option<&str>,
    normalized: Option<&NormalizedInstructions>,
    code: &[u8],
) -> ArtifactFingerprint {
    let mut bytes = Vec::new();
    bytes.extend(name.unwrap_or_default().as_bytes());
    bytes.push(0);
    bytes.extend(section.unwrap_or_default().as_bytes());
    bytes.push(0);
    if let Some(normalized) = normalized {
        bytes.extend(normalized.version.as_bytes());
        bytes.push(0);
        bytes.extend(&normalized.bytes);
    } else {
        bytes.extend(code);
    }
    ArtifactFingerprint::from_content("pe-coff-symbol", &bytes)
}

fn data_fingerprint(name: Option<&str>, data: &[u8]) -> ArtifactFingerprint {
    let mut bytes = Vec::new();
    bytes.extend(name.unwrap_or_default().as_bytes());
    bytes.push(0);
    bytes.extend(data);
    ArtifactFingerprint::from_content("pe-coff-data", &bytes)
}

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::PeCoff,
        message,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
    use object::{BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
    use proptest::prelude::*;

    fn coff_fixture() -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
        object.add_symbol(Symbol {
            name: b"render".to_vec(),
            value: offset,
            size: 2,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        object.write().expect("write COFF fixture")
    }

    #[test]
    fn parses_a_coff_function_without_executing_it() {
        let ir = PeCoffBackend
            .parse(&coff_fixture())
            .expect("parse COFF fixture");
        assert_eq!(ir.format, ArtifactFormat::PeCoff);
        assert_eq!(ir.symbols.len(), 1, "{ir:#?}");
        assert!(ir.capabilities.symbols);
        assert_eq!(ir.symbols[0].name.as_deref(), Some("render"));
        assert_eq!(ir.symbols[0].code, vec![0x90, 0xc3]);
        assert_eq!(
            ir.symbols[0]
                .normalized
                .as_ref()
                .map(|value| value.version.as_str()),
            Some(PE_COFF_NORMALIZATION_VERSION)
        );
    }

    #[test]
    fn other_bytes_do_not_claim_the_backend() {
        assert!(!PeCoffBackend.detects(b"not an object"));
        assert!(matches!(
            PeCoffBackend.parse(b"not an object"),
            Err(ArtifactError::Malformed { .. })
        ));
    }

    #[test]
    fn a_pdb_is_not_guessed_for_a_coff_object() {
        let error = PeCoffBackend
            .parse_with_pdb(&coff_fixture(), Some(b"not a pdb"))
            .expect_err("COFF objects cannot have an external PDB companion");
        assert!(error.to_string().contains("COFF object"));
    }

    #[test]
    fn pdb_identity_requires_guid_and_accepts_a_newer_age() {
        assert!(pdb_identity_matches([1; 16], 3, [1; 16], 3));
        assert!(pdb_identity_matches([1; 16], 4, [1; 16], 3));
        assert!(!pdb_identity_matches([2; 16], 4, [1; 16], 3));
        assert!(!pdb_identity_matches([1; 16], 2, [1; 16], 3));
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = PeCoffBackend.parse(&bytes);
        }
    }
}
