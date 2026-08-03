use super::*;
use crate::symbols::demangle;
use crate::x86::normalize_x86;
use object::write::{Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SymbolFlags, SymbolKind, SymbolScope,
};
use proptest::prelude::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
    object.add_symbol(Symbol {
        name: b"returning".to_vec(),
        value: offset,
        size: 2,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let data = object.section_id(StandardSection::ReadOnlyData);
    object.append_section_data(data, b"read-only fixture", 1);
    object.write().expect("write ELF fixture")
}

fn build_id_fixture(build_id: &[u8]) -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let offset = object.append_section_data(text, &[0xc3], 1);
    object.add_symbol(Symbol {
        name: b"returning".to_vec(),
        value: offset,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let note = object.add_section(
        Vec::new(),
        b".note.gnu.build-id".to_vec(),
        SectionKind::Note,
    );
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(4_u32).to_le_bytes());
    bytes.extend_from_slice(
        &(u32::try_from(build_id.len()).expect("test build ID fits")).to_le_bytes(),
    );
    bytes.extend_from_slice(&(3_u32).to_le_bytes());
    bytes.extend_from_slice(b"GNU\0");
    bytes.extend_from_slice(build_id);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    object.append_section_data(note, &bytes, 4);
    object.write().expect("write ELF build-ID fixture")
}

fn call_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let caller_offset = object.append_section_data(text, &[0xe8, 0, 0, 0, 0, 0xc3], 1);
    let target_offset = object.append_section_data(text, &[0xc3], 1);
    let target = object.add_symbol(Symbol {
        name: b"target".to_vec(),
        value: target_offset,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object.add_symbol(Symbol {
        name: b"caller".to_vec(),
        value: caller_offset,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object
        .add_relocation(
            text,
            Relocation {
                offset: caller_offset + 1,
                symbol: target,
                addend: -4,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Relative,
                    encoding: RelocationEncoding::Generic,
                    size: 32,
                },
            },
        )
        .expect("add direct call relocation");
    object.write().expect("write ELF call fixture")
}

fn linked_call_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let caller_offset = object.append_section_data(text, &[0xe8, 1, 0, 0, 0, 0xc3], 1);
    let target_offset = object.append_section_data(text, &[0xc3], 1);
    object.add_symbol(Symbol {
        name: b"target".to_vec(),
        value: target_offset,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object.add_symbol(Symbol {
        name: b"caller".to_vec(),
        value: caller_offset,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object.write().expect("write linked ELF call fixture")
}

fn init_array_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let constructor_offset = object.append_section_data(text, &[0xc3], 1);
    let constructor = object.add_symbol(Symbol {
        name: b"constructor".to_vec(),
        value: constructor_offset,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    let init_array = object.add_section(Vec::new(), b".init_array".to_vec(), SectionKind::Data);
    let offset = object.append_section_data(init_array, &[0; 8], 8);
    object
        .add_relocation(
            init_array,
            Relocation {
                offset,
                symbol: constructor,
                addend: 0,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Absolute,
                    encoding: RelocationEncoding::Generic,
                    size: 64,
                },
            },
        )
        .expect("add constructor relocation");
    object.write().expect("write ELF init-array fixture")
}

fn stripped_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    object.append_section_data(text, &[0x90, 0xc3], 1);
    object.write().expect("write stripped ELF fixture")
}

fn zero_sized_text_symbols_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let first_offset = object.append_section_data(text, &[0x90], 1);
    let second_offset = object.append_section_data(text, &[0xc3], 1);
    for (name, offset) in [
        (b"first".as_slice(), first_offset),
        (b"second", second_offset),
    ] {
        object.add_symbol(Symbol {
            name: name.to_vec(),
            value: offset,
            size: 0,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    object
        .write()
        .expect("write zero-sized ELF text symbols fixture")
}

fn zero_sized_alias_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
    for (name, size) in [(b"implementation".as_slice(), 2), (b"alias", 0)] {
        object.add_symbol(Symbol {
            name: name.to_vec(),
            value: offset,
            size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    object.write().expect("write zero-sized ELF alias fixture")
}

fn immediate_that_contains_call_opcode_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let offset = object.append_section_data(text, &[0xb8, 0xe8, 0, 0, 0, 0xc3], 1);
    object.add_symbol(Symbol {
        name: b"constant".to_vec(),
        value: offset,
        size: 6,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object
        .write()
        .expect("write immediate containing call opcode fixture")
}

fn relocatable_sections_with_overlapping_addresses_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    for (section_name, symbol_name) in [
        (b".text.first".as_slice(), b"first".as_slice()),
        (b".text.second".as_slice(), b"second".as_slice()),
    ] {
        let section = object.add_section(Vec::new(), section_name.to_vec(), SectionKind::Text);
        let offset = object.append_section_data(section, &[0xe8, 0xfb, 0xff, 0xff, 0xff, 0xc3], 1);
        object.add_symbol(Symbol {
            name: symbol_name.to_vec(),
            value: offset,
            size: 6,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
    }
    object
        .write()
        .expect("write relocatable overlapping-section fixture")
}

#[test]
fn parses_sections_and_sized_text_symbols() {
    let artifact = ElfBackend.parse(&fixture()).expect("fixture parses");
    assert_eq!(artifact.format, ArtifactFormat::Elf);
    assert!(artifact.capabilities.symbols);
    assert!(
        artifact
            .sections
            .iter()
            .any(|section| section.executable && section.name.as_deref() == Some(".text"))
    );
    assert_eq!(artifact.symbols.len(), 1);
    assert_eq!(artifact.symbols[0].name.as_deref(), Some("returning"));
    assert!(artifact.symbols[0].exported);
    assert_eq!(artifact.symbols[0].code, vec![0x90, 0xc3]);
    assert!(artifact.capabilities.data_segments);
    assert_eq!(artifact.data_segments.len(), 1);
    assert_eq!(artifact.data_segments[0].bytes, b"read-only fixture");
}

#[test]
fn section_sized_native_data_is_not_reported_as_measured_duplicate_data() {
    let artifact = ElfBackend.parse(&fixture()).expect("fixture parses");
    let sizes = crate::metrics::classify_sizes(&artifact);

    assert!(!artifact.capabilities.independent_data_segments);
    assert_eq!(sizes.duplicated_data_bytes, None);
    assert!(
        sizes
            .assumptions
            .iter()
            .any(|assumption| assumption.contains("independently established data regions"))
    );
}

#[test]
fn zero_sized_text_symbols_trim_padding_without_losing_the_alias_record() {
    let artifact = ElfBackend
        .parse(&zero_sized_text_symbols_fixture())
        .expect("zero-sized symbol fixture parses");
    assert_eq!(artifact.symbols.len(), 2, "{artifact:#?}");
    assert_eq!(artifact.symbols[0].name.as_deref(), Some("first"));
    assert_eq!(artifact.symbols[0].code, Vec::<u8>::new());
    assert_eq!(artifact.symbols[0].size, 0);
    assert!(artifact.symbols[0].size_inferred);
    assert_eq!(artifact.symbols[1].name.as_deref(), Some("second"));
    assert_eq!(artifact.symbols[1].code, vec![0xc3]);
    assert!(artifact.symbols[1].size_inferred);
}

#[test]
fn zero_sized_elf_alias_is_retained_without_claiming_implementation_bytes() {
    let artifact = ElfBackend
        .parse(&zero_sized_alias_fixture())
        .expect("zero-sized alias fixture parses");
    let alias = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("alias"))
        .expect("alias record");
    let implementation = artifact
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
fn malformed_or_other_inputs_return_errors_instead_of_panicking() {
    assert!(matches!(
        ElfBackend.parse(b"not ELF"),
        Err(ArtifactError::WrongFormat { .. })
    ));
    assert!(matches!(
        ElfBackend.parse(b"\x7fELF\x02"),
        Err(ArtifactError::Malformed { .. })
    ));
}

#[test]
fn external_debug_companion_without_a_matching_build_id_is_rejected() {
    let error = ElfBackend
        .parse_with_debug_companion(&fixture(), Some(&fixture()))
        .expect_err("fixture has no GNU build ID");
    assert!(error.to_string().contains("build ID"));
}

#[test]
fn external_debug_companion_with_the_same_build_id_is_accepted() {
    let artifact = build_id_fixture(&[7; 20]);
    let parsed = ElfBackend
        .parse_with_debug_companion(&artifact, Some(&artifact))
        .expect("matching build IDs permit the debug companion");
    assert_eq!(parsed.format, ArtifactFormat::Elf);
}

proptest! {
    #[test]
    fn arbitrary_and_truncated_elf_bytes_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut truncated = b"\x7fELF".to_vec();
        truncated.extend(&bytes);
        for input in [&bytes, &truncated] {
            let result = catch_unwind(AssertUnwindSafe(|| ElfBackend.parse(input)));
            prop_assert!(result.is_ok());
        }
    }
}

#[test]
fn stripped_elf_degrades_to_an_inferred_text_region() {
    let artifact = ElfBackend
        .parse(&stripped_fixture())
        .expect("stripped fixture parses");
    assert!(artifact.capabilities.symbols);
    assert_eq!(artifact.symbols.len(), 1);
    assert!(artifact.symbols[0].name.is_none());
    assert!(artifact.symbols[0].size_inferred);
    assert_eq!(artifact.symbols[0].code, vec![0x90, 0xc3]);
}

#[test]
fn parsing_the_same_elf_twice_is_deterministic() {
    let bytes = fixture();
    assert_eq!(
        ElfBackend.parse(&bytes).expect("first fixture parses"),
        ElfBackend.parse(&bytes).expect("second fixture parses")
    );
}

#[test]
fn fixture_ir_snapshot_is_current() {
    let artifact = ElfBackend.parse(&fixture()).expect("fixture parses");
    let rendered = serde_json::to_string_pretty(&artifact).expect("IR serializes");
    assert_eq!(
        rendered,
        include_str!("../../tests/golden/minimal-ir-v1.json").trim_end()
    );
}

#[test]
fn x86_call_relocation_becomes_a_direct_local_edge() {
    let artifact = ElfBackend.parse(&call_fixture()).expect("fixture parses");
    let caller = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("caller"))
        .expect("caller symbol");
    let target = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("target"))
        .expect("target symbol");
    assert!(artifact.capabilities.call_graph);
    assert!(artifact.capabilities.relocations);
    assert_eq!(artifact.calls.len(), 1);
    assert_eq!(artifact.relocations.len(), 1);
    assert_eq!(artifact.relocations[0].target.as_deref(), Some("target"));
    assert_eq!(artifact.calls[0].caller, caller.fingerprint);
    assert_eq!(artifact.calls[0].target, Some(target.fingerprint));
    assert!(artifact.calls[0].unresolved.is_none());
}

#[test]
fn x86_rel32_call_without_a_relocation_resolves_from_symbol_addresses() {
    let artifact = ElfBackend
        .parse(&linked_call_fixture())
        .expect("linked fixture parses");
    let caller = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("caller"))
        .expect("caller symbol");
    let target = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("target"))
        .expect("target symbol");
    assert!(artifact.calls.iter().any(|call| {
        call.caller == caller.fingerprint
            && call.target == Some(target.fingerprint)
            && call.unresolved.is_none()
    }));
}

#[test]
fn relocatable_call_join_uses_section_and_address() {
    let artifact = ElfBackend
        .parse(&relocatable_sections_with_overlapping_addresses_fixture())
        .expect("relocatable overlapping-section fixture parses");
    assert_eq!(artifact.symbols.len(), 2, "{artifact:#?}");
    assert_eq!(artifact.calls.len(), 2, "{artifact:#?}");
    for symbol in &artifact.symbols {
        let call = artifact
            .calls
            .iter()
            .find(|call| call.caller == symbol.fingerprint)
            .expect("each section-local function has one direct call");
        assert_eq!(call.target, Some(symbol.fingerprint));
        assert!(call.unresolved.is_none());
    }
}

#[test]
fn x86_call_opcode_inside_an_immediate_does_not_make_a_call_edge() {
    let artifact = ElfBackend
        .parse(&immediate_that_contains_call_opcode_fixture())
        .expect("fixture parses");
    assert!(artifact.calls.is_empty(), "{artifact:#?}");
}

#[test]
fn entry_address_becomes_a_stable_entry_point_without_becoming_an_id() {
    let fingerprint = ArtifactFingerprint::from_content("test", b"entry");
    let addresses = HashMap::from([(0x0040_1000, fingerprint)]);
    let mut artifact = ArtifactIr::empty(ArtifactFormat::Elf, b"fixture");

    record_entry_point(0x0040_1000, &addresses, &mut artifact);
    record_entry_point(0, &addresses, &mut artifact);

    assert_eq!(artifact.entry_points, vec![fingerprint]);
}

#[test]
fn init_array_relocation_becomes_a_conservative_entry_point() {
    let artifact = ElfBackend
        .parse(&init_array_fixture())
        .expect("init-array fixture parses");
    let constructor = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("constructor"))
        .expect("constructor symbol");

    assert_eq!(artifact.entry_points, vec![constructor.fingerprint]);
}

#[test]
fn linked_init_array_pointers_become_conservative_entry_points() {
    let first = ArtifactFingerprint::from_content("test", b"first");
    let second = ArtifactFingerprint::from_content("test", b"second");
    let addresses = HashMap::from([(0x0040_1000, first), (0x0040_2000, second)]);

    assert_eq!(
        pointer_roots(
            &[
                0x00, 0x10, 0x40, 0x00, 0, 0, 0, 0, 0x00, 0x20, 0x40, 0x00, 0, 0, 0, 0
            ],
            true,
            Endianness::Little,
            &addresses,
        ),
        BTreeSet::from([first, second])
    );
    assert_eq!(
        pointer_roots(
            &[0x00, 0x40, 0x10, 0x00],
            false,
            Endianness::Big,
            &addresses
        ),
        BTreeSet::from([first])
    );
}

#[test]
fn x86_normalization_keeps_instruction_shape_and_drops_immediates() {
    let first = normalize_x86(&[0xb8, 1, 0, 0, 0, 0xc3], Architecture::X86_64).unwrap();
    let second = normalize_x86(&[0xb8, 2, 0, 0, 0, 0xc3], Architecture::X86_64).unwrap();
    assert_eq!(first.version, ELF_NORMALIZATION_VERSION);
    assert_eq!(first.bytes, second.bytes);
    let near_call = normalize_x86(&[0xe8, 1, 0, 0, 0, 0xc3], Architecture::X86_64).unwrap();
    let other_near_call =
        normalize_x86(&[0xe8, 255, 255, 255, 255, 0xc3], Architecture::X86_64).unwrap();
    assert_eq!(near_call.bytes, other_near_call.bytes);
    assert!(normalize_x86(&[0x0f], Architecture::X86_64).is_none());
    assert!(normalize_x86(&[0xc3], Architecture::Aarch64).is_none());
}

#[test]
fn symbol_identity_uses_normalized_code_not_offsets_or_immediates() {
    let first = [0xb8, 1, 0, 0, 0, 0xc3];
    let second = [0xb8, 2, 0, 0, 0, 0xc3];
    let first_normalized = normalize_x86(&first, Architecture::X86_64);
    let second_normalized = normalize_x86(&second, Architecture::X86_64);
    assert_eq!(
        symbol_fingerprint(
            Some("function"),
            Some(".text"),
            first_normalized.as_ref(),
            &first,
        ),
        symbol_fingerprint(
            Some("function"),
            Some(".text"),
            second_normalized.as_ref(),
            &second,
        )
    );
    assert_ne!(
        symbol_fingerprint(
            Some("function"),
            Some(".text"),
            first_normalized.as_ref(),
            &first,
        ),
        symbol_fingerprint(
            Some("other"),
            Some(".text"),
            first_normalized.as_ref(),
            &first,
        )
    );
}

#[test]
fn demangling_keeps_unknown_names_and_handles_itanium_symbols() {
    assert_eq!(demangle("ordinary_name"), "ordinary_name");
    assert!(demangle("_Z3fooi").contains("foo"));
}

#[test]
fn dwarf_relative_paths_keep_their_declared_directory_context_without_reading_source() {
    assert_eq!(
        crate::dwarf::resolve_source_path("src/main.cpp", None, Some("/work/tree")),
        "/work/tree/src/main.cpp"
    );
    assert_eq!(
        crate::dwarf::resolve_source_path("header.hpp", Some("include"), Some("/work/tree")),
        "/work/tree/include/header.hpp"
    );
    assert_eq!(
        crate::dwarf::resolve_source_path("entry.cpp", Some("/other/build"), Some("/work/tree")),
        "/other/build/entry.cpp"
    );
    assert_eq!(
        crate::dwarf::resolve_source_path(
            "/outside/entry.cpp",
            Some("include"),
            Some("/work/tree")
        ),
        "/outside/entry.cpp"
    );
    // A directory already ending in a separator does not gain a second one.
    // Producers write it both ways, and the same source spelled two ways
    // would be two sources to everything downstream that matches on it.
    assert_eq!(
        crate::dwarf::resolve_source_path("src/main.cpp", None, Some("/work/tree/")),
        "/work/tree/src/main.cpp"
    );
    assert_eq!(
        crate::dwarf::resolve_source_path("header.hpp", Some("include/"), Some("/work/tree/")),
        "/work/tree/include/header.hpp"
    );
}
