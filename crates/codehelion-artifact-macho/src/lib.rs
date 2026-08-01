//! Mach-O implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the inspected artifact. It deliberately records only container
//! facts; DWARF and dSYM source locations remain a correlation-layer concern.

use std::collections::{BTreeSet, HashMap};

use codehelion_artifact::symbols::demangle;
use codehelion_artifact::x86::{X86_NORMALIZATION_VERSION, normalize_x86, trim_inferred_padding};
use codehelion_artifact::{
    ArtifactBackend, ArtifactCapabilities, ArtifactDataSegment, ArtifactError, ArtifactFingerprint,
    ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactIr, ArtifactRelocation,
    ArtifactSection, ArtifactSymbol, NormalizedInstructions,
};
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind};

/// Parser backend for Mach-O executable and relocatable objects.
#[derive(Debug, Default, Clone, Copy)]
pub struct MachOBackend;

/// Version of the shared x86 instruction-shape normalization representation.
pub const MACHO_NORMALIZATION_VERSION: &str = X86_NORMALIZATION_VERSION;

impl ArtifactBackend for MachOBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::MachO
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        matches!(
            bytes.get(..4),
            Some(
                [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                    | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                    | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            )
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
        if !self.detects(bytes) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::MachO,
            });
        }
        let (artifact, offset) = mach_o_slice(bytes)?;
        let file = object::File::parse(artifact).map_err(|error| malformed(error.to_string()))?;
        if file.format() != object::BinaryFormat::MachO {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::MachO,
            });
        }
        let debug_file = debug_companion
            .map(|companion| {
                let (companion, _) = mach_o_slice(companion)?;
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
        shift_file_offsets(&mut ir, offset);
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

fn mach_o_slice(bytes: &[u8]) -> Result<(&[u8], u64), ArtifactError> {
    match object::FileKind::parse(bytes).map_err(|error| malformed(error.to_string()))? {
        object::FileKind::MachO32 | object::FileKind::MachO64 => Ok((bytes, 0)),
        object::FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(bytes).map_err(|error| malformed(error.to_string()))?;
            fat_slice(&fat, bytes)
        }
        object::FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(bytes).map_err(|error| malformed(error.to_string()))?;
            fat_slice(&fat, bytes)
        }
        _ => Err(ArtifactError::WrongFormat {
            expected: ArtifactFormat::MachO,
        }),
    }
}

fn fat_slice<'a, Fat: FatArch>(
    fat: &object::read::macho::MachOFatFile<'a, Fat>,
    bytes: &'a [u8],
) -> Result<(&'a [u8], u64), ArtifactError> {
    let arch = fat
        .arches()
        .first()
        .ok_or_else(|| malformed("fat Mach-O has no architecture slices".to_owned()))?;
    let (offset, _) = arch.file_range();
    let slice = arch
        .data(bytes)
        .map_err(|error| malformed(error.to_string()))?;
    Ok((slice, offset))
}

fn shift_file_offsets(ir: &mut ArtifactIr, offset: u64) {
    if offset == 0 {
        return;
    }
    for section in &mut ir.sections {
        section.offset = section.offset.saturating_add(offset);
    }
    for segment in &mut ir.data_segments {
        segment.offset = segment.offset.saturating_add(offset);
    }
    for symbol in &mut ir.symbols {
        symbol.offset = symbol.offset.saturating_add(offset);
    }
    for relocation in &mut ir.relocations {
        relocation.offset = relocation.offset.saturating_add(offset);
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
        if symbol.is_undefined() {
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
            kind: ArtifactImportKind::Other,
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
                symbol.section_index() == Some(section_index)
                    && symbol.kind() == object::SymbolKind::Text
                    && !symbol.is_undefined()
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
            let code = if symbol.size() == 0 {
                trim_inferred_padding(code, file.architecture())
            } else {
                code
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
                size: u64::try_from(code.len()).unwrap_or(u64::MAX),
                size_inferred: symbol.size() == 0,
                code: code.to_vec(),
                normalized,
                inline_stack: Vec::new(),
            });
            addresses.insert(
                fingerprint,
                (
                    symbol.address(),
                    u64::try_from(code.len()).unwrap_or(u64::MAX),
                ),
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
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
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

    fn macho_undefined_import_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::X86_64,
            Endianness::Little,
        );
        object.add_symbol(Symbol {
            name: b"_external_call".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        object
            .write()
            .expect("write Mach-O undefined import fixture")
    }

    fn fat_macho_fixture() -> Vec<u8> {
        let inner = macho_fixture();
        let offset = 256_u32;
        let mut bytes = Vec::new();
        bytes.extend([0xca, 0xfe, 0xba, 0xbe]);
        bytes.extend(1_u32.to_be_bytes());
        bytes.extend(0x0100_0007_u32.to_be_bytes());
        bytes.extend(3_u32.to_be_bytes());
        bytes.extend(offset.to_be_bytes());
        bytes.extend(
            u32::try_from(inner.len())
                .expect("fixture slice length fits")
                .to_be_bytes(),
        );
        bytes.extend(8_u32.to_be_bytes());
        bytes.resize(offset as usize, 0);
        bytes.extend(inner);
        bytes
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
    fn records_undefined_macho_symbols_as_imports() {
        let ir = MachOBackend
            .parse(&macho_undefined_import_fixture())
            .expect("parse Mach-O undefined import fixture");
        assert_eq!(ir.imports.len(), 1, "{ir:#?}");
        assert_eq!(ir.imports[0].name.as_deref(), Some("__external_call"));
        assert_eq!(ir.imports[0].kind, ArtifactImportKind::Other);
    }

    #[test]
    fn parses_a_fat_macho_slice_without_losing_outer_identity() {
        let bytes = fat_macho_fixture();
        assert!(MachOBackend.detects(&bytes));
        let ir = MachOBackend
            .parse(&bytes)
            .expect("fat Mach-O fixture parses");
        assert_eq!(ir.observed_bytes, bytes.len() as u64);
        assert_eq!(
            ir.fingerprint,
            ArtifactFingerprint::from_content("artifact", &bytes)
        );
        assert_eq!(ir.symbols.len(), 1, "{ir:#?}");
        assert!(ir.symbols[0].offset >= 256);
    }

    #[test]
    fn other_bytes_do_not_claim_the_backend() {
        assert!(!MachOBackend.detects(b"not an object"));
        assert!(matches!(
            MachOBackend.parse(b"not an object"),
            Err(ArtifactError::WrongFormat { .. })
        ));
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = MachOBackend.parse(&bytes);
        }
    }
}
