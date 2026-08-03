//! Cross-format contract tests for native artifact collection.

#![allow(clippy::expect_used)]

use codehelion_artifact::elf::ElfBackend;
use codehelion_artifact::macho::MachOBackend;
use codehelion_artifact::pe::PeCoffBackend;
use codehelion_artifact::{ArtifactBackend, ArtifactImportKind};
use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

fn native_fixture(format: BinaryFormat) -> Vec<u8> {
    let mut object = WriteObject::new(format, Architecture::X86_64, Endianness::Little);
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
    object.write().expect("write native consistency fixture")
}

#[test]
fn equivalent_native_objects_share_symbol_identity_and_import_kind() {
    let artifacts = [
        ElfBackend
            .parse(&native_fixture(BinaryFormat::Elf))
            .expect("ELF fixture parses"),
        MachOBackend
            .parse(&native_fixture(BinaryFormat::MachO))
            .expect("Mach-O fixture parses"),
        PeCoffBackend
            .parse(&native_fixture(BinaryFormat::Coff))
            .expect("COFF fixture parses"),
    ];

    let expected_fingerprint = artifacts[0].symbols[0].fingerprint;
    assert_eq!(
        expected_fingerprint.to_hex(),
        "1928e2c0d684a7fb82a31d5b43d6eff7"
    );
    for artifact in &artifacts {
        assert_eq!(artifact.symbols.len(), 1, "{artifact:#?}");
        assert_eq!(artifact.symbols[0].fingerprint, expected_fingerprint);
        assert_eq!(artifact.imports.len(), 1, "{artifact:#?}");
        assert_eq!(artifact.imports[0].kind, ArtifactImportKind::Function);
    }
}
