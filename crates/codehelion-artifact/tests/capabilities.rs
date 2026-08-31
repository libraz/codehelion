//! A backend's declared capabilities bound what its parses actually establish.

#![allow(clippy::expect_used)]

use codehelion_artifact::{ArtifactBackend, ArtifactCapabilities, ArtifactIr};
use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

/// A minimal object with one code symbol and one read-only data section.
fn fixture(format: BinaryFormat) -> Vec<u8> {
    let mut object = WriteObject::new(format, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
    object.add_symbol(Symbol {
        name: b"returning".to_vec(),
        value: offset,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let data = object.section_id(StandardSection::ReadOnlyData);
    object.append_section_data(data, b"read-only fixture", 1);
    object.write().expect("write the capability fixture")
}

/// Whether every field `parsed` established was declared as possible.
///
/// Unreadable debug information is an observation about one parse rather than
/// a declared ability, so it takes no part in the comparison.
fn declared_covers(declared: ArtifactCapabilities, parsed: &ArtifactIr) -> bool {
    let parsed = parsed.capabilities;
    let fields = [
        (declared.symbols, parsed.symbols),
        (declared.call_graph, parsed.call_graph),
        (declared.source_mapping, parsed.source_mapping),
        (declared.normalized_duplicates, parsed.normalized_duplicates),
        (
            declared.independent_data_segments,
            parsed.independent_data_segments,
        ),
        (declared.relocations, parsed.relocations),
        (declared.data_segments, parsed.data_segments),
    ];
    fields
        .into_iter()
        .all(|(declared, parsed)| declared || !parsed)
}

#[test]
fn a_native_backend_declares_everything_its_parse_establishes() {
    for (backend, bytes) in [
        (
            Box::new(codehelion_artifact::elf::ElfBackend) as Box<dyn ArtifactBackend>,
            fixture(BinaryFormat::Elf),
        ),
        (
            Box::new(codehelion_artifact::macho::MachOBackend),
            fixture(BinaryFormat::MachO),
        ),
        (
            Box::new(codehelion_artifact::pe::PeCoffBackend),
            fixture(BinaryFormat::Coff),
        ),
    ] {
        let ir = backend.parse(&bytes).expect("parse the capability fixture");
        assert!(
            declared_covers(backend.capabilities(), &ir),
            "{} parses more than it declares: {:?} against {:?}",
            backend.format(),
            backend.capabilities(),
            ir.capabilities
        );
        assert!(
            !backend.capabilities().debug_info_unreadable,
            "{} declares a per-parse observation",
            backend.format()
        );
    }
}

#[test]
fn native_backends_reaching_the_same_collection_declare_it_the_same_way() {
    let elf = codehelion_artifact::elf::ElfBackend.capabilities();
    let macho = codehelion_artifact::macho::MachOBackend.capabilities();
    let pe = codehelion_artifact::pe::PeCoffBackend.capabilities();

    for other in [macho, pe] {
        assert_eq!(elf.symbols, other.symbols);
        assert_eq!(elf.source_mapping, other.source_mapping);
        assert_eq!(elf.normalized_duplicates, other.normalized_duplicates);
        assert_eq!(elf.relocations, other.relocations);
        assert_eq!(elf.data_segments, other.data_segments);
        assert_eq!(
            elf.independent_data_segments,
            other.independent_data_segments
        );
    }
}

#[test]
fn a_declared_capability_does_not_depend_on_the_input() {
    let backend = codehelion_artifact::elf::ElfBackend;
    let declared = backend.capabilities();

    let _ = backend.parse(&fixture(BinaryFormat::Elf));
    let _ = backend.parse(b"not an artifact");

    assert_eq!(backend.capabilities(), declared);
}
