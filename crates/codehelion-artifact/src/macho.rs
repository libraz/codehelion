//! Mach-O implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the inspected artifact. It deliberately records only container
//! facts; DWARF and dSYM source locations remain a correlation-layer concern.

use std::collections::HashMap;

use crate::native::{
    collect_sections, collect_text_symbols, collect_undefined_imports, symbol_fingerprint,
};
use crate::x86::X86_NORMALIZATION_VERSION;
use crate::{
    ArtifactBackend, ArtifactCapabilities, ArtifactError, ArtifactFingerprint, ArtifactFormat,
    ArtifactIr,
};
use object::Object;
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};

#[cfg(test)]
use crate::ArtifactImportKind;

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
        self.parse_with_architecture(bytes, None, None)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        ArtifactCapabilities {
            symbols: true,
            call_graph: false,
            source_mapping: false,
            debug_info_unreadable: false,
            normalized_duplicates: false,
            independent_data_segments: false,
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
        self.parse_with_architecture(bytes, debug_companion, None)
    }

    /// Parse a Mach-O artifact while selecting one universal-binary architecture.
    ///
    /// A multi-slice input requires `architecture`; selecting a slice by file
    /// order would make equivalent comparison commands inspect different code.
    ///
    /// # Errors
    ///
    /// Returns an error when the requested architecture is absent, or when a
    /// universal input supplies more than one slice without a selection.
    pub fn parse_with_architecture(
        &self,
        bytes: &[u8],
        debug_companion: Option<&[u8]>,
        architecture: Option<&str>,
    ) -> Result<ArtifactIr, ArtifactError> {
        if !self.detects(bytes) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::MachO,
            });
        }
        let selection = mach_o_slice(bytes, architecture)?;
        let artifact = selection.bytes;
        let offset = selection.offset;
        let file = object::File::parse(artifact).map_err(|error| malformed(error.to_string()))?;
        if file.format() != object::BinaryFormat::MachO {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::MachO,
            });
        }
        if let Some(requested) = architecture
            && !architecture_selector_matches(architecture_name(file.architecture()), requested)
        {
            return Err(malformed(format!(
                "Mach-O architecture is {}, not requested {requested}",
                architecture_name(file.architecture())
            )));
        }
        let debug_file = debug_companion
            .map(|companion| {
                let companion = mach_o_slice(companion, architecture)?;
                let companion = object::File::parse(companion.bytes)
                    .map_err(|error| malformed(error.to_string()))?;
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
        let selected_architecture = if selection.architecture == "unknown" {
            architecture_name(file.architecture()).to_owned()
        } else {
            selection.architecture
        };
        let mut ir = ArtifactIr::empty(ArtifactFormat::MachO, bytes);
        ir.architecture = Some(selected_architecture);
        ir.skipped_architectures = selection.skipped_architectures;
        collect_sections(&file, &mut ir).map_err(|error| malformed(error.to_string()))?;
        collect_undefined_imports(file.symbols(), &mut ir);
        let collected_addresses = collect_symbols(&file, &mut ir)?;
        let symbol_addresses = if ir.symbols.is_empty() {
            infer_text_regions(&file, &mut ir)?
        } else {
            collected_addresses
        };
        crate::dwarf::attach_dwarf_frames(
            debug_file.as_ref().unwrap_or(&file),
            &symbol_addresses,
            &mut ir,
        );
        shift_file_offsets(&mut ir, offset);
        ir.capabilities = ArtifactCapabilities {
            symbols: !ir.symbols.is_empty(),
            call_graph: false,
            source_mapping: !ir.source_mappings.is_empty(),
            debug_info_unreadable: ir.capabilities.debug_info_unreadable,
            normalized_duplicates: crate::x86::supports_normalized_duplicates(file.architecture()),
            independent_data_segments: false,
            relocations: !ir.relocations.is_empty(),
            data_segments: !ir.data_segments.is_empty(),
        };
        Ok(ir)
    }
}

struct MachOSlice<'a> {
    bytes: &'a [u8],
    offset: u64,
    architecture: String,
    skipped_architectures: Vec<String>,
}

fn mach_o_slice<'a>(
    bytes: &'a [u8],
    requested_architecture: Option<&str>,
) -> Result<MachOSlice<'a>, ArtifactError> {
    match object::FileKind::parse(bytes).map_err(|error| malformed(error.to_string()))? {
        object::FileKind::MachO32 | object::FileKind::MachO64 => Ok(MachOSlice {
            bytes,
            offset: 0,
            architecture: "unknown".to_owned(),
            skipped_architectures: Vec::new(),
        }),
        object::FileKind::MachOFat32 => {
            let fat = MachOFatFile32::parse(bytes).map_err(|error| malformed(error.to_string()))?;
            fat_slice_with_architecture(&fat, bytes, requested_architecture)
        }
        object::FileKind::MachOFat64 => {
            let fat = MachOFatFile64::parse(bytes).map_err(|error| malformed(error.to_string()))?;
            fat_slice_with_architecture(&fat, bytes, requested_architecture)
        }
        _ => Err(ArtifactError::WrongFormat {
            expected: ArtifactFormat::MachO,
        }),
    }
}

fn fat_slice_with_architecture<'a, Fat: FatArch>(
    fat: &object::read::macho::MachOFatFile<'a, Fat>,
    bytes: &'a [u8],
    requested_architecture: Option<&str>,
) -> Result<MachOSlice<'a>, ArtifactError> {
    let arches = fat.arches();
    let available = fat_architecture_labels(arches);
    let selected_index = match (arches, requested_architecture) {
        ([], _) => {
            return Err(malformed(
                "fat Mach-O has no architecture slices".to_owned(),
            ));
        }
        ([_], None) => 0,
        (_, Some(requested)) => {
            let matches: Vec<_> = available
                .iter()
                .enumerate()
                .filter_map(|(index, name)| (name == requested).then_some(index))
                .collect();
            match matches.as_slice() {
                [index] => *index,
                [] => {
                    return Err(malformed(format!(
                        "fat Mach-O has no {requested} slice (available: {})",
                        available.join(", ")
                    )));
                }
                _ => {
                    return Err(malformed(
                        "fat Mach-O architecture selector is ambiguous".to_owned(),
                    ));
                }
            }
        }
        (_, None) => {
            return Err(malformed(format!(
                "fat Mach-O has multiple architecture slices (available: {}); select one with --arch",
                available.join(", ")
            )));
        }
    };
    let arch = &arches[selected_index];
    let (offset, _) = arch.file_range();
    let slice = arch
        .data(bytes)
        .map_err(|error| malformed(error.to_string()))?;
    let selected = available[selected_index].clone();
    let skipped_architectures = available
        .into_iter()
        .filter(|available| available != &selected)
        .collect();
    Ok(MachOSlice {
        bytes: slice,
        offset,
        architecture: selected,
        skipped_architectures,
    })
}

fn architecture_selector_matches(architecture: &str, selector: &str) -> bool {
    selector.split_once(':').map_or(selector, |(base, _)| base) == architecture
}

fn fat_architecture_labels<Fat: FatArch>(arches: &[Fat]) -> Vec<String> {
    let bases: Vec<_> = arches
        .iter()
        .map(|arch| architecture_name(arch.architecture()))
        .collect();
    arches
        .iter()
        .zip(&bases)
        .map(|(arch, base)| {
            if bases.iter().filter(|other| *other == base).count() == 1 {
                (*base).to_owned()
            } else {
                format!("{base}:{}", arch.cpusubtype())
            }
        })
        .collect()
}

const fn architecture_name(architecture: object::Architecture) -> &'static str {
    match architecture {
        object::Architecture::Aarch64 => "aarch64",
        object::Architecture::Arm => "arm",
        object::Architecture::I386 => "i386",
        object::Architecture::X86_64 => "x86_64",
        object::Architecture::PowerPc => "powerpc",
        object::Architecture::PowerPc64 => "powerpc64",
        _ => "unknown",
    }
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

fn collect_symbols(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<HashMap<ArtifactFingerprint, (u64, u64)>, ArtifactError> {
    collect_text_symbols(file, ir)
        .map(|ranges| {
            ranges
                .into_iter()
                .map(|range| (range.fingerprint, (range.address, range.size)))
                .collect()
        })
        .map_err(|error| malformed(error.to_string()))
}
/// Represent each text section when a stripped Mach-O has no symbol table.
///
/// The inferred region is explicitly marked and uses only the section's bytes;
/// it lets release artifacts remain analyzable without manufacturing names or
/// source locations.
fn infer_text_regions(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<HashMap<ArtifactFingerprint, (u64, u64)>, ArtifactError> {
    let ranges = crate::native::infer_text_regions(file, ir, |section, normalized, data| {
        symbol_fingerprint(None, section, normalized, data)
    })
    .map_err(|error| malformed(error.to_string()))?;
    Ok(ranges
        .into_iter()
        .map(|(fingerprint, address, size)| (fingerprint, (address, size)))
        .collect())
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

    fn macho_fixture_without_symbols() -> Vec<u8> {
        let mut object = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::X86_64,
            Endianness::Little,
        );
        let text = object.section_id(StandardSection::Text);
        object.append_section_data(text, &[0x90, 0xc3], 1);
        object.write().expect("write symbol-free Mach-O fixture")
    }

    fn macho_zero_sized_alias_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::X86_64,
            Endianness::Little,
        );
        let text = object.section_id(StandardSection::Text);
        let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
        for (name, size) in [(b"implementation".as_slice(), 2), (b"alias", 0)] {
            object.add_symbol(Symbol {
                name: name.to_vec(),
                value: offset,
                size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Dynamic,
                weak: false,
                section: SymbolSection::Section(text),
                flags: SymbolFlags::None,
            });
        }
        object
            .write()
            .expect("write zero-sized Mach-O alias fixture")
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

    fn universal_macho_fixture() -> Vec<u8> {
        let x86_64 = macho_fixture();
        let aarch64 = {
            let mut object = WriteObject::new(
                BinaryFormat::MachO,
                Architecture::Aarch64,
                Endianness::Little,
            );
            let text = object.section_id(StandardSection::Text);
            let offset = object.append_section_data(text, &[0x1f, 0x20, 0x03, 0xd5], 4);
            object.add_symbol(Symbol {
                name: b"render_arm64".to_vec(),
                value: offset,
                size: 4,
                kind: SymbolKind::Text,
                scope: SymbolScope::Dynamic,
                weak: false,
                section: SymbolSection::Section(text),
                flags: SymbolFlags::None,
            });
            object.write().expect("write AArch64 Mach-O fixture")
        };
        let x86_64_offset = 256_u32;
        let aarch64_offset = 512_u32;
        let mut bytes = Vec::new();
        bytes.extend([0xca, 0xfe, 0xba, 0xbe]);
        bytes.extend(2_u32.to_be_bytes());
        for (cpu_type, cpu_subtype, offset, inner) in [
            (0x0100_0007_u32, 3_u32, x86_64_offset, &x86_64),
            (0x0100_000c_u32, 0_u32, aarch64_offset, &aarch64),
        ] {
            bytes.extend(cpu_type.to_be_bytes());
            bytes.extend(cpu_subtype.to_be_bytes());
            bytes.extend(offset.to_be_bytes());
            bytes.extend(
                u32::try_from(inner.len())
                    .expect("fixture slice length fits")
                    .to_be_bytes(),
            );
            bytes.extend(8_u32.to_be_bytes());
        }
        bytes.resize(x86_64_offset as usize, 0);
        bytes.extend(x86_64);
        bytes.resize(aarch64_offset as usize, 0);
        bytes.extend(aarch64);
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
    fn symbol_free_macho_keeps_an_explicitly_inferred_text_region() {
        let ir = MachOBackend
            .parse(&macho_fixture_without_symbols())
            .expect("parse symbol-free Mach-O fixture");
        assert_eq!(ir.symbols.len(), 1, "{ir:#?}");
        assert!(ir.capabilities.symbols);
        assert!(ir.symbols[0].size_inferred);
        assert_eq!(ir.symbols[0].name, None);
        assert_eq!(ir.symbols[0].code, vec![0x90, 0xc3]);
    }

    #[test]
    fn zero_sized_macho_alias_is_retained_without_claiming_implementation_bytes() {
        let ir = MachOBackend
            .parse(&macho_zero_sized_alias_fixture())
            .expect("parse zero-sized Mach-O alias fixture");
        let at_start: Vec<_> = ir
            .symbols
            .iter()
            .filter(|symbol| symbol.offset == ir.symbols[0].offset)
            .collect();
        assert_eq!(at_start.len(), 2, "{ir:#?}");
        assert_eq!(
            at_start
                .iter()
                .filter(|symbol| symbol.code.is_empty())
                .count(),
            1,
            "{ir:#?}"
        );
        assert_eq!(
            at_start
                .iter()
                .filter(|symbol| symbol.code == [0x90, 0xc3])
                .count(),
            1,
            "{ir:#?}"
        );
        let alias = at_start
            .iter()
            .find(|symbol| symbol.code.is_empty())
            .expect("empty alias record");
        assert!(alias.size_inferred);
        assert_eq!(alias.size, 0);
    }

    #[test]
    fn records_undefined_macho_symbols_as_imports() {
        let ir = MachOBackend
            .parse(&macho_undefined_import_fixture())
            .expect("parse Mach-O undefined import fixture");
        assert_eq!(ir.imports.len(), 1, "{ir:#?}");
        assert_eq!(ir.imports[0].name.as_deref(), Some("__external_call"));
        assert_eq!(ir.imports[0].kind, ArtifactImportKind::Function);
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
    fn universal_macho_requires_an_explicit_architecture_selection() {
        let bytes = universal_macho_fixture();
        let error = MachOBackend
            .parse(&bytes)
            .expect_err("multi-slice input is ambiguous");
        assert!(error.to_string().contains("--arch"), "{error}");
        assert!(error.to_string().contains("x86_64"), "{error}");
        assert!(error.to_string().contains("aarch64"), "{error}");
    }

    #[test]
    fn universal_macho_records_the_selected_and_skipped_architectures() {
        let bytes = universal_macho_fixture();
        let ir = MachOBackend
            .parse_with_architecture(&bytes, None, Some("aarch64"))
            .expect("explicit AArch64 slice parses");
        assert_eq!(ir.architecture.as_deref(), Some("aarch64"));
        assert_eq!(ir.skipped_architectures, ["x86_64"]);
        assert_eq!(ir.symbols[0].name.as_deref(), Some("_render_arm64"));
        assert!(ir.symbols[0].offset >= 512);
    }

    #[test]
    fn universal_macho_rejects_a_missing_architecture_selection() {
        let error = MachOBackend
            .parse_with_architecture(&universal_macho_fixture(), None, Some("i386"))
            .expect_err("unavailable slice is rejected");
        assert!(error.to_string().contains("no i386 slice"), "{error}");
    }

    #[test]
    fn thin_macho_rejects_an_architecture_that_does_not_match_its_header() {
        let error = MachOBackend
            .parse_with_architecture(&macho_fixture(), None, Some("aarch64"))
            .expect_err("thin architecture mismatch is rejected");
        assert!(
            error.to_string().contains("not requested aarch64"),
            "{error}"
        );
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
