//! A backend's declared capabilities bound what its parses actually establish.
//!
//! The sweep below walks the crate's format support table rather than a list
//! written here, so a format added to the boundary is checked without anyone
//! remembering to add it. The `archive` feature turns on the four object
//! backends it delegates to, which is every backend there is, so gating the
//! file on it is what makes the sweep complete rather than partial.

#![cfg(feature = "archive")]
#![allow(clippy::expect_used, clippy::panic)]

use codehelion_artifact::{
    ArtifactBackend, ArtifactCapabilities, ArtifactFormat, ArtifactIr, FORMAT_SUPPORT,
    extension_table, format_support,
};
use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

/// A minimal object with one code symbol and one read-only data section.
fn object_fixture(format: BinaryFormat) -> Vec<u8> {
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

/// One exported function, one call, one data segment and a name section.
fn wasm_fixture() -> Vec<u8> {
    let mut module = vec![
        0, 97, 115, 109, 1, 0, 0, 0, // magic and version
        1, 4, 1, 0x60, 0, 0, // one type: [] -> []
        3, 3, 2, 0, 0, // two functions of that type
        7, 7, 1, 3, b'f', b'o', b'o', 0, 0, // export the first as "foo"
        10, 9, 2, 4, 0, 0x10, 1, 0x0b, 2, 0, 0x0b, // bodies: call 1; end / end
        11, 6, 1, 1, 3, b'a', b'b', b'c', // one passive data segment
    ];
    // A recorded source-map URL, which is the source evidence this format has.
    module.extend([0, 26, 16]);
    module.extend(b"sourceMappingURL");
    module.extend(b"maps.json");
    module
}

/// One archive member header, with the two-byte alignment padding archives use.
fn archive_member(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut member = Vec::new();
    let name = format!("{name}/");
    member.extend(format!("{name:<16}").as_bytes());
    member.extend(b"0           0     0     100644  ");
    member.extend(format!("{:<10}", bytes.len()).as_bytes());
    member.extend(b"`\n");
    member.extend(bytes);
    if !bytes.len().is_multiple_of(2) {
        member.push(b'\n');
    }
    member
}

fn archive_fixture() -> Vec<u8> {
    let mut archive = b"!<arch>\n".to_vec();
    archive.extend(archive_member(
        "left.obj",
        &object_fixture(BinaryFormat::Coff),
    ));
    archive.extend(archive_member(
        "right.obj",
        &object_fixture(BinaryFormat::Coff),
    ));
    archive
}

/// A well-formed input for `format`.
///
/// The match names every format, so a format added to the boundary cannot
/// reach the sweep without an input to sweep it with.
fn fixture(format: ArtifactFormat) -> Vec<u8> {
    match format {
        ArtifactFormat::Wasm => wasm_fixture(),
        ArtifactFormat::Elf => object_fixture(BinaryFormat::Elf),
        ArtifactFormat::MachO => object_fixture(BinaryFormat::MachO),
        ArtifactFormat::PeCoff => object_fixture(BinaryFormat::Coff),
        ArtifactFormat::Archive => archive_fixture(),
    }
}

/// The backend that owns `format`.
fn backend(format: ArtifactFormat) -> Box<dyn ArtifactBackend> {
    match format {
        ArtifactFormat::Wasm => Box::new(codehelion_artifact::wasm::WasmBackend),
        ArtifactFormat::Elf => Box::new(codehelion_artifact::elf::ElfBackend),
        ArtifactFormat::MachO => Box::new(codehelion_artifact::macho::MachOBackend),
        ArtifactFormat::PeCoff => Box::new(codehelion_artifact::pe::PeCoffBackend),
        ArtifactFormat::Archive => Box::new(codehelion_artifact::archive::ArchiveBackend),
    }
}

/// Whether every field `parsed` established was declared as possible.
///
/// Unreadable debug information is an observation about one parse rather than
/// a declared ability, so it takes no part in the comparison.
fn undeclared_fields(declared: ArtifactCapabilities, parsed: &ArtifactIr) -> Vec<&'static str> {
    let parsed = parsed.capabilities;
    [
        ("symbols", declared.symbols, parsed.symbols),
        ("call_graph", declared.call_graph, parsed.call_graph),
        (
            "source_mapping",
            declared.source_mapping,
            parsed.source_mapping,
        ),
        (
            "normalized_duplicates",
            declared.normalized_duplicates,
            parsed.normalized_duplicates,
        ),
        (
            "independent_data_segments",
            declared.independent_data_segments,
            parsed.independent_data_segments,
        ),
        ("relocations", declared.relocations, parsed.relocations),
        (
            "data_segments",
            declared.data_segments,
            parsed.data_segments,
        ),
    ]
    .into_iter()
    .filter(|(_, declared, parsed)| *parsed && !*declared)
    .map(|(field, _, _)| field)
    .collect()
}

#[test]
fn every_backend_declares_everything_its_parse_establishes() {
    for row in &FORMAT_SUPPORT {
        let backend = backend(row.format);
        let bytes = fixture(row.format);
        let ir = backend
            .parse(&bytes)
            .unwrap_or_else(|error| panic!("parse the {} fixture: {error}", row.format));
        assert_eq!(
            ir.format, row.format,
            "{} answered with another format",
            row.format
        );
        assert!(
            undeclared_fields(backend.capabilities(), &ir).is_empty(),
            "{} parses more than it declares: {:?}",
            row.format,
            undeclared_fields(backend.capabilities(), &ir)
        );
        assert!(
            !backend.capabilities().debug_info_unreadable,
            "{} declares a per-parse observation",
            row.format
        );
    }
}

/// The declaration and the support table are one statement, not two.
#[test]
fn a_backend_declares_exactly_its_row_of_the_support_table() {
    for row in &FORMAT_SUPPORT {
        assert_eq!(
            backend(row.format).capabilities(),
            row.capabilities,
            "{} declares something other than its row",
            row.format
        );
        assert_eq!(
            backend(row.format).format(),
            row.format,
            "{} answers for another row",
            row.format
        );
    }
}

/// The document states what the definitions say, and is compared with them
/// rather than maintained beside them.
#[test]
fn the_format_document_carries_the_generated_capability_table() {
    let document = include_str!("../FORMAT_SUPPORT.md");
    let table = extension_table();
    assert!(
        document.contains(&table),
        "FORMAT_SUPPORT.md does not carry the generated table; it should read:\n\n{table}\n"
    );
}

/// A format the document names outside its table would be a second statement
/// about the same facts, which is what the table exists to prevent.
#[test]
fn the_format_document_names_no_format_the_table_omits() {
    let document = include_str!("../FORMAT_SUPPORT.md");
    for row in &FORMAT_SUPPORT {
        assert!(
            document.contains(row.format.name()),
            "FORMAT_SUPPORT.md omits {}",
            row.format
        );
    }
}

#[test]
fn native_backends_reaching_the_same_collection_declare_it_the_same_way() {
    let elf = format_support(ArtifactFormat::Elf).capabilities;
    let macho = format_support(ArtifactFormat::MachO).capabilities;
    let pe = format_support(ArtifactFormat::PeCoff).capabilities;

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
    for row in &FORMAT_SUPPORT {
        let backend = backend(row.format);
        let declared = backend.capabilities();

        let _ = backend.parse(&fixture(row.format));
        let _ = backend.parse(b"not an artifact");

        assert_eq!(backend.capabilities(), declared, "{}", row.format);
    }
}
