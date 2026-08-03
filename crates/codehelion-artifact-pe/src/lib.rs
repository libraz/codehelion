//! PE and COFF implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the inspected artifact. PDB source locations are intentionally a
//! separate correlation input: this parser establishes only facts present in
//! the PE or COFF container itself.

use std::collections::{BTreeSet, HashMap};
use std::io::Cursor;

use codehelion_artifact::native::{
    collect_sections, collect_text_symbols, collect_undefined_imports, symbol_fingerprint,
};
use codehelion_artifact::x86::X86_NORMALIZATION_VERSION;
use codehelion_artifact::{
    ArtifactBackend, ArtifactCapabilities, ArtifactError, ArtifactFingerprint, ArtifactFormat,
    ArtifactIr,
};
use object::Object;
use pdb::{FallibleIterator, PDB};

#[cfg(test)]
use codehelion_artifact::ArtifactImportKind;

/// Parser backend for PE images and COFF objects.
#[derive(Debug, Default, Clone, Copy)]
pub struct PeCoffBackend;

/// Version of the shared x86 instruction-shape normalization representation.
pub const PE_COFF_NORMALIZATION_VERSION: &str = X86_NORMALIZATION_VERSION;

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
            debug_info_unreadable: false,
            normalized_duplicates: false,
            independent_data_segments: false,
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
        if !self.detects(bytes) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::PeCoff,
            });
        }
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
        collect_sections(&file, &mut ir).map_err(|error| malformed(error.to_string()))?;
        collect_undefined_imports(file.symbols(), &mut ir);
        let symbol_ranges = collect_symbols(&file, &mut ir)?;
        if ir.symbols.is_empty() {
            infer_text_regions(&file, &mut ir)?;
        }
        if let Some(pdb_bytes) = pdb_bytes {
            collect_pdb_frames(&file, pdb_bytes, &symbol_ranges, &mut ir)?;
        }
        ir.capabilities = ArtifactCapabilities {
            symbols: !ir.symbols.is_empty(),
            call_graph: false,
            source_mapping: !ir.source_mappings.is_empty(),
            debug_info_unreadable: false,
            normalized_duplicates: codehelion_artifact::x86::supports_normalized_duplicates(
                file.architecture(),
            ),
            independent_data_segments: false,
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

fn collect_symbols(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<Vec<SymbolRange>, ArtifactError> {
    collect_text_symbols(file, ir)
        .map(|ranges| {
            ranges
                .into_iter()
                .map(|range| SymbolRange {
                    fingerprint: range.fingerprint,
                    start: range.address,
                    end: range.address.saturating_add(range.size),
                })
                .collect()
        })
        .map_err(|error| malformed(error.to_string()))
}

/// Preserve executable code in a PE/COFF image that has no COFF symbols.
///
/// Linked release images commonly omit the symbol table. One explicitly
/// inferred region per text section says that code was observed while making
/// clear that no function boundary was available.
fn infer_text_regions(file: &object::File<'_>, ir: &mut ArtifactIr) -> Result<(), ArtifactError> {
    codehelion_artifact::native::infer_text_regions(file, ir, |section, normalized, data| {
        symbol_fingerprint(None, section, normalized, data)
    })
    .map_err(|error| malformed(error.to_string()))?;
    Ok(())
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
                    evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Pdb,
                    source: source.into_owned(),
                    line: Some(line.line_start),
                    column: line.column_start.filter(|column| *column != 0),
                },
            ));
        }
    }
    frames.sort_by_key(|(address, _)| *address);
    let symbol_rows: HashMap<_, _> = ir
        .symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| (symbol.fingerprint, index))
        .collect();
    for range in symbol_ranges {
        let frame_start = frames.partition_point(|(address, _)| *address < range.start);
        let mut symbol_frames: Vec<_> = frames[frame_start..]
            .iter()
            .take_while(|(address, _)| *address < range.end)
            .map(|(_, frame)| frame.clone())
            .collect();
        symbol_frames.sort_by(|left, right| {
            (&left.source, left.line, left.column).cmp(&(&right.source, right.line, right.column))
        });
        symbol_frames.dedup();
        if symbol_frames.is_empty() {
            continue;
        }
        if let Some(index) = symbol_rows.get(&range.fingerprint) {
            ir.symbols[*index].inline_stack = symbol_frames;
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
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
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

    fn coff_fixture_without_symbols() -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        object.append_section_data(text, &[0x90, 0xc3], 1);
        object.write().expect("write symbol-free COFF fixture")
    }

    fn coff_zero_sized_alias_fixture() -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
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
        object.write().expect("write zero-sized COFF alias fixture")
    }

    fn coff_undefined_import_fixture() -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        object.add_symbol(Symbol {
            name: b"external_call".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        object.write().expect("write COFF undefined import fixture")
    }

    #[test]
    fn sorted_pdb_line_addresses_are_sliced_to_each_symbol_range() {
        let frames = [(2, "before"), (10, "start"), (12, "inside"), (15, "after")];
        let start = frames.partition_point(|(address, _)| *address < 10);
        let matched: Vec<_> = frames[start..]
            .iter()
            .take_while(|(address, _)| *address < 15)
            .map(|(_, label)| *label)
            .collect();

        assert_eq!(matched, ["start", "inside"]);
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
    fn symbol_free_coff_keeps_an_explicitly_inferred_text_region() {
        let ir = PeCoffBackend
            .parse(&coff_fixture_without_symbols())
            .expect("parse symbol-free COFF fixture");
        assert_eq!(ir.symbols.len(), 1, "{ir:#?}");
        assert!(ir.capabilities.symbols);
        assert!(ir.symbols[0].size_inferred);
        assert_eq!(ir.symbols[0].name, None);
        assert_eq!(ir.symbols[0].code, vec![0x90, 0xc3]);
    }

    #[test]
    fn zero_sized_coff_alias_is_retained_without_claiming_implementation_bytes() {
        let ir = PeCoffBackend
            .parse(&coff_zero_sized_alias_fixture())
            .expect("parse zero-sized COFF alias fixture");
        let alias = ir
            .symbols
            .iter()
            .find(|symbol| symbol.name.as_deref() == Some("alias"))
            .expect("alias record");
        let implementation = ir
            .symbols
            .iter()
            .find(|symbol| symbol.name.as_deref() == Some("implementation"))
            .expect("implementation record");
        assert!(alias.size_inferred);
        assert_eq!(alias.size, 0);
        assert!(alias.code.is_empty());
        assert_eq!(implementation.code, vec![0x90, 0xc3]);
    }

    #[test]
    fn records_undefined_coff_symbols_as_imports() {
        let ir = PeCoffBackend
            .parse(&coff_undefined_import_fixture())
            .expect("parse COFF undefined import fixture");
        assert_eq!(ir.imports.len(), 1, "{ir:#?}");
        assert_eq!(ir.imports[0].name.as_deref(), Some("external_call"));
        assert_eq!(ir.imports[0].kind, ArtifactImportKind::Function);
    }

    #[test]
    fn other_bytes_do_not_claim_the_backend() {
        assert!(!PeCoffBackend.detects(b"not an object"));
        assert!(matches!(
            PeCoffBackend.parse(b"not an object"),
            Err(ArtifactError::WrongFormat { .. })
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
