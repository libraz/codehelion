//! Mach-O implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the inspected artifact. It deliberately records only container
//! facts; DWARF and dSYM source locations remain a correlation-layer concern.

use std::collections::{BTreeSet, HashMap};

use codehelion_artifact::{
    ArtifactBackend, ArtifactCapabilities, ArtifactDataSegment, ArtifactError, ArtifactFingerprint,
    ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactIr, ArtifactRelocation,
    ArtifactSection, ArtifactSymbol, NormalizedInstructions,
};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolKind,
};

/// Parser backend for Mach-O executable and relocatable objects.
#[derive(Debug, Default, Clone, Copy)]
pub struct MachOBackend;

/// Version of the x86 instruction-shape normalization representation.
pub const MACHO_NORMALIZATION_VERSION: &str = "x86-operand-shape-v1";

impl ArtifactBackend for MachOBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::MachO
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        matches!(
            bytes.get(..4),
            Some([0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe])
        )
    }

    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
        self.parse_with_debug_companion(bytes, None)
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

impl MachOBackend {
    /// Parse a Mach-O artifact with an optional matching dSYM DWARF companion.
    ///
    /// The companion must be a Mach-O debug image bearing exactly the same
    /// `LC_UUID`. A dSYM's inner `Contents/Resources/DWARF/<name>` file is the
    /// debug image passed here; neither it nor the inspected artifact is run.
    ///
    /// # Errors
    ///
    /// Returns an error when either container is malformed or a supplied
    /// companion lacks the inspected image's UUID.
    pub fn parse_with_debug_companion(
        &self,
        bytes: &[u8],
        debug_companion: Option<&[u8]>,
    ) -> Result<ArtifactIr, ArtifactError> {
        let file = object::File::parse(bytes).map_err(|error| malformed(error.to_string()))?;
        if file.format() != object::BinaryFormat::MachO {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::MachO,
            });
        }
        let debug_file = debug_companion
            .map(|companion| {
                let companion =
                    object::File::parse(companion).map_err(|error| malformed(error.to_string()))?;
                if companion.format() != object::BinaryFormat::MachO
                    || !matching_uuid(&file, &companion)
                {
                    return Err(malformed(
                        "external debug companion does not have the artifact's Mach-O UUID"
                            .to_owned(),
                    ));
                }
                Ok(companion)
            })
            .transpose()?;
        let mut ir = ArtifactIr::empty(ArtifactFormat::MachO, bytes);
        collect_sections(&file, &mut ir)?;
        collect_imports(&file, &mut ir);
        let symbol_addresses = collect_symbols(&file, &mut ir)?;
        codehelion_artifact::dwarf::attach_dwarf_frames(
            debug_file.as_ref().unwrap_or(&file),
            &symbol_addresses,
            &mut ir,
        );
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

fn matching_uuid(artifact: &object::File<'_>, companion: &object::File<'_>) -> bool {
    matches!(
        (artifact.mach_uuid(), companion.mach_uuid()),
        (Ok(Some(artifact)), Ok(Some(companion))) if artifact == companion
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
) -> Result<HashMap<ArtifactFingerprint, (u64, u64)>, ArtifactError> {
    let mut addresses = HashMap::new();
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
            addresses.insert(
                fingerprint,
                (symbol.address(), u64::try_from(size).unwrap_or(u64::MAX)),
            );
        }
    }
    Ok(addresses)
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

fn normalize_x86(bytes: &[u8], architecture: Architecture) -> Option<NormalizedInstructions> {
    let bitness = match architecture {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return None,
    };
    let mut decoder = Decoder::with_ip(bitness, bytes, 0, DecoderOptions::NONE);
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
        version: MACHO_NORMALIZATION_VERSION.to_owned(),
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
    ArtifactFingerprint::from_content("macho-symbol", &bytes)
}

fn data_fingerprint(name: Option<&str>, data: &[u8]) -> ArtifactFingerprint {
    let mut bytes = Vec::new();
    bytes.extend(name.unwrap_or_default().as_bytes());
    bytes.push(0);
    bytes.extend(data);
    ArtifactFingerprint::from_content("macho-data", &bytes)
}

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::MachO,
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

    fn macho_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::X86_64,
            Endianness::Little,
        );
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
        object.write().expect("write Mach-O fixture")
    }

    #[test]
    fn parses_a_macho_function_without_executing_it() {
        let ir = MachOBackend
            .parse(&macho_fixture())
            .expect("parse Mach-O fixture");
        assert_eq!(ir.format, ArtifactFormat::MachO);
        assert_eq!(ir.symbols.len(), 1, "{ir:#?}");
        assert!(ir.capabilities.symbols);
        assert_eq!(ir.symbols[0].name.as_deref(), Some("_render"));
        assert_eq!(ir.symbols[0].code, vec![0x90, 0xc3]);
        assert_eq!(
            ir.symbols[0]
                .normalized
                .as_ref()
                .map(|value| value.version.as_str()),
            Some(MACHO_NORMALIZATION_VERSION)
        );
    }

    #[test]
    fn other_bytes_do_not_claim_the_backend() {
        assert!(!MachOBackend.detects(b"not an object"));
        assert!(matches!(
            MachOBackend.parse(b"not an object"),
            Err(ArtifactError::Malformed { .. })
        ));
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = MachOBackend.parse(&bytes);
        }
    }
}
