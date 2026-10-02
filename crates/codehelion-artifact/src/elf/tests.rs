use super::*;
use crate::native::symbol_fingerprint;
use crate::symbols::demangle;
use crate::x86::normalize_x86;
use object::write::{Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SymbolFlags, SymbolKind, SymbolScope,
};

pub(super) fn fixture() -> Vec<u8> {
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

/// One exported function whose only call is `call *%rax`, which is how a C++
/// virtual dispatch is compiled.
fn indirect_call_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let caller_offset = object.append_section_data(text, &[0xff, 0xd0, 0xc3], 1);
    let callee_offset = object.append_section_data(text, &[0xc3], 1);
    object.add_symbol(Symbol {
        name: b"caller".to_vec(),
        value: caller_offset,
        size: 3,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object.add_symbol(Symbol {
        name: b"reached_only_indirectly".to_vec(),
        value: callee_offset,
        size: 1,
        kind: SymbolKind::Text,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    object.write().expect("write ELF indirect call fixture")
}

/// A direct call relocated to a symbol this object does not define.
fn undefined_target_call_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let caller_offset = object.append_section_data(text, &[0xe8, 0, 0, 0, 0, 0xc3], 1);
    let external = object.add_symbol(Symbol {
        name: b"defined_elsewhere".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Undefined,
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
                symbol: external,
                addend: -4,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::PltRelative,
                    encoding: RelocationEncoding::X86Branch,
                    size: 32,
                },
            },
        )
        .expect("add external call relocation");
    object.write().expect("write ELF external call fixture")
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

/// Two sized names at one offset (a constructor pair) beside an equal-bytes
/// function elsewhere in the section.
fn sized_alias_fixture() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let first = object.append_section_data(text, &[0x90, 0xc3], 1);
    let second = object.append_section_data(text, &[0x90, 0xc3], 1);
    for (name, value) in [
        (b"complete".as_slice(), first),
        (b"base", first),
        (b"twin", second),
    ] {
        object.add_symbol(Symbol {
            name: name.to_vec(),
            value,
            size: 2,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    object.write().expect("write sized ELF alias fixture")
}

/// A relocatable object with one function per text section.
fn function_sections_fixture(count: usize) -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    for index in 0..count {
        let section = object.add_section(
            Vec::new(),
            format!(".text.f{index}").into_bytes(),
            SectionKind::Text,
        );
        let offset = object.append_section_data(section, &[0x90, 0xc3], 1);
        object.add_symbol(Symbol {
            name: format!("f{index}").into_bytes(),
            value: offset,
            size: 2,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
    }
    object.write().expect("write function-sections fixture")
}

/// One text section holding the named functions, each with an optional
/// relocation `(offset in function, target name, kind, size, addend)`.
type FunctionSpec<'a> = (
    &'a str,
    &'a [u8],
    SymbolScope,
    Option<(u64, &'a str, RelocationKind, u8, i64)>,
);

fn functions_fixture(functions: &[FunctionSpec<'_>], pointer_to: Option<&str>) -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text = object.section_id(StandardSection::Text);
    let mut symbols = HashMap::new();
    let mut offsets = Vec::new();
    for (name, code, scope, _) in functions {
        let offset = object.append_section_data(text, code, 1);
        let symbol = object.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: offset,
            size: code.len() as u64,
            kind: SymbolKind::Text,
            scope: *scope,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        symbols.insert(*name, symbol);
        offsets.push(offset);
    }
    for ((_, _, _, relocation), base) in functions.iter().zip(offsets) {
        let Some((at, target, kind, size, addend)) = relocation else {
            continue;
        };
        object
            .add_relocation(
                text,
                Relocation {
                    offset: base + at,
                    symbol: symbols[target],
                    addend: *addend,
                    flags: RelocationFlags::Generic {
                        kind: *kind,
                        encoding: RelocationEncoding::Generic,
                        size: *size,
                    },
                },
            )
            .expect("add relocation");
    }
    if let Some(target) = pointer_to {
        let data = object.section_id(StandardSection::Data);
        let at = object.append_section_data(data, &[0; 8], 8);
        object
            .add_relocation(
                data,
                Relocation {
                    offset: at,
                    symbol: symbols[target],
                    addend: 0,
                    flags: RelocationFlags::Generic {
                        kind: RelocationKind::Absolute,
                        encoding: RelocationEncoding::Generic,
                        size: 64,
                    },
                },
            )
            .expect("add data pointer relocation");
    }
    object.write().expect("write function fixture")
}

fn dead_symbol_names(artifact: &ArtifactIr) -> (Vec<String>, bool) {
    let dead = crate::metrics::dead_code_candidates(artifact).expect("an export establishes roots");
    let names = dead
        .symbols
        .iter()
        .filter_map(|fingerprint| {
            artifact
                .symbols
                .iter()
                .find(|symbol| symbol.fingerprint == *fingerprint)
                .and_then(|symbol| symbol.name.clone())
        })
        .collect();
    (names, dead.definitive)
}

#[test]
fn a_tail_jump_to_another_function_is_a_call_edge() {
    let artifact = ElfBackend
        .parse(&functions_fixture(
            &[
                (
                    "entry",
                    &[0xe9, 0, 0, 0, 0],
                    SymbolScope::Linkage,
                    Some((1, "tail", RelocationKind::Relative, 32, -4)),
                ),
                ("tail", &[0xc3], SymbolScope::Compilation, None),
                ("unused", &[0x90, 0xc3], SymbolScope::Compilation, None),
            ],
            None,
        ))
        .expect("tail jump fixture parses");
    let tail = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("tail"))
        .expect("tail record");

    assert!(
        artifact
            .calls
            .iter()
            .any(|call| call.target == Some(tail.fingerprint)),
        "{:#?}",
        artifact.calls
    );
    let (dead, definitive) = dead_symbol_names(&artifact);
    assert_eq!(dead, vec!["unused".to_owned()]);
    assert!(definitive);
}

#[test]
fn a_jump_through_a_register_keeps_dead_code_a_candidate_list() {
    let artifact = ElfBackend
        .parse(&functions_fixture(
            &[
                ("entry", &[0xff, 0xe0], SymbolScope::Linkage, None),
                ("unused", &[0x90, 0xc3], SymbolScope::Compilation, None),
            ],
            None,
        ))
        .expect("indirect jump fixture parses");

    assert_eq!(artifact.calls.len(), 1, "{artifact:#?}");
    assert_eq!(
        artifact.calls[0].unresolved,
        Some(UnresolvedCall::NativeIndirect)
    );
    assert!(!dead_symbol_names(&artifact).1);
    assert_eq!(
        crate::metrics::classify_sizes(&artifact).retained_bytes,
        None
    );
}

#[test]
fn jumps_inside_a_function_and_through_a_table_are_not_transfers() {
    let artifact = ElfBackend
        .parse(&functions_fixture(
            &[
                // jmp +0; jne +0; jmp [rax*8 + 0x1000]; ret
                (
                    "entry",
                    &[
                        0xeb, 0x00, 0x75, 0x00, 0xff, 0x24, 0xc5, 0x00, 0x10, 0x00, 0x00, 0xc3,
                    ],
                    SymbolScope::Linkage,
                    None,
                ),
                ("unused", &[0x90, 0xc3], SymbolScope::Compilation, None),
            ],
            None,
        ))
        .expect("internal jump fixture parses");

    assert!(artifact.calls.is_empty(), "{:#?}", artifact.calls);
}

#[test]
fn a_function_whose_address_is_loaded_is_not_dead() {
    let artifact = ElfBackend
        .parse(&functions_fixture(
            &[
                // lea rax, [rip + callback]; ret
                (
                    "entry",
                    &[0x48, 0x8d, 0x05, 0, 0, 0, 0, 0xc3],
                    SymbolScope::Linkage,
                    Some((3, "callback", RelocationKind::Relative, 32, -4)),
                ),
                ("callback", &[0xc3], SymbolScope::Compilation, None),
                (
                    "caller",
                    &[0xe8, 0, 0, 0, 0, 0xc3],
                    SymbolScope::Linkage,
                    Some((1, "helper", RelocationKind::Relative, 32, -4)),
                ),
                (
                    "helper",
                    &[0x90, 0x90, 0x90, 0xc3],
                    SymbolScope::Compilation,
                    None,
                ),
                ("unused", &[0x90, 0xc3], SymbolScope::Compilation, None),
            ],
            None,
        ))
        .expect("address-taken fixture parses");
    let callback = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("callback"))
        .expect("callback record");

    assert!(artifact.indirect_references.contains(&callback.fingerprint));
    assert_eq!(dead_symbol_names(&artifact).0, vec!["unused".to_owned()]);
}

#[test]
fn a_function_address_computed_in_a_linked_image_is_not_dead() {
    let mut bytes = functions_fixture(
        &[
            // lea rax, [rip + 1] reaches the byte after the next instruction.
            (
                "entry",
                &[0x48, 0x8d, 0x05, 1, 0, 0, 0, 0xc3],
                SymbolScope::Linkage,
                None,
            ),
            ("callback", &[0xc3], SymbolScope::Compilation, None),
            (
                "caller",
                &[0xe8, 1, 0, 0, 0, 0xc3],
                SymbolScope::Linkage,
                None,
            ),
            (
                "helper",
                &[0x90, 0x90, 0x90, 0xc3],
                SymbolScope::Compilation,
                None,
            ),
            ("unused", &[0x90, 0xc3], SymbolScope::Compilation, None),
        ],
        None,
    );
    // Mark the object executable so addresses join across sections.
    bytes[16] = 2;
    let artifact = ElfBackend.parse(&bytes).expect("linked fixture parses");

    assert_eq!(artifact.indirect_references.len(), 1, "{artifact:#?}");
    assert_eq!(dead_symbol_names(&artifact).0, vec!["unused".to_owned()]);
}

#[test]
fn a_function_pointer_stored_in_data_is_not_dead() {
    let artifact = ElfBackend
        .parse(&functions_fixture(
            &[
                ("entry", &[0xc3], SymbolScope::Linkage, None),
                ("handler", &[0x90, 0xc3], SymbolScope::Compilation, None),
                (
                    "caller",
                    &[0xe8, 0, 0, 0, 0, 0xc3],
                    SymbolScope::Linkage,
                    Some((1, "helper", RelocationKind::Relative, 32, -4)),
                ),
                (
                    "helper",
                    &[0x90, 0x90, 0x90, 0xc3],
                    SymbolScope::Compilation,
                    None,
                ),
                (
                    "unused",
                    &[0x90, 0x90, 0xc3],
                    SymbolScope::Compilation,
                    None,
                ),
            ],
            Some("handler"),
        ))
        .expect("data pointer fixture parses");

    assert_eq!(artifact.indirect_references.len(), 1);
    assert_eq!(dead_symbol_names(&artifact).0, vec!["unused".to_owned()]);
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
    assert!(alias.code.is_empty(), "code: {:?}", alias.code);
    assert_eq!(implementation.code, vec![0x90, 0xc3]);
}

#[test]
fn sized_elf_alias_does_not_claim_the_bytes_of_the_symbol_it_shares() {
    let artifact = ElfBackend
        .parse(&sized_alias_fixture())
        .expect("sized alias fixture parses");
    let by_name = |name: &str| {
        artifact
            .symbols
            .iter()
            .find(|symbol| symbol.name.as_deref() == Some(name))
            .expect("symbol record")
    };
    assert_eq!(artifact.symbols.len(), 3);
    assert_eq!(by_name("complete").size, 2);
    assert!(
        by_name("base").code.is_empty(),
        "{:?}",
        by_name("base").code
    );
    assert_eq!(by_name("base").size, 0);
    assert_eq!(by_name("base").offset, by_name("complete").offset);
    assert_eq!(by_name("twin").size, 2);

    let report = crate::metrics::find_duplicates(&artifact);
    assert_eq!(report.exact.len(), 1, "{report:#?}");
    let group = &report.exact[0];
    assert_eq!(group.duplicated_bytes, 2);
    let mut offsets: Vec<_> = group.members.iter().map(|member| member.offset).collect();
    offsets.sort_unstable();
    offsets.dedup();
    assert_eq!(offsets.len(), group.members.len(), "no two members overlap");
}

#[test]
fn an_object_with_a_text_section_per_function_keeps_every_function() {
    let count = 20_000;
    let artifact = ElfBackend
        .parse(&function_sections_fixture(count))
        .expect("function-sections fixture parses");
    assert_eq!(artifact.symbols.len(), count);
    assert!(artifact.symbols.iter().all(|symbol| symbol.size == 2));
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

/// A call through a register reaches a callee this backend cannot name, so it
/// contributes an unresolved edge. Without one, a function that only virtual
/// dispatch reaches is reported as provably dead.
#[test]
fn an_indirect_call_records_an_unresolved_edge_instead_of_disappearing() {
    let artifact = ElfBackend
        .parse(&indirect_call_fixture())
        .expect("indirect call fixture parses");
    let caller = artifact
        .symbols
        .iter()
        .find(|symbol| symbol.name.as_deref() == Some("caller"))
        .expect("caller symbol");

    assert_eq!(artifact.calls.len(), 1, "{artifact:#?}");
    assert_eq!(artifact.calls[0].caller, caller.fingerprint);
    assert_eq!(artifact.calls[0].target, None);
    assert_eq!(
        artifact.calls[0].unresolved,
        Some(UnresolvedCall::NativeIndirect)
    );

    let dead =
        crate::metrics::dead_code_candidates(&artifact).expect("an export establishes roots");
    assert!(!dead.definitive, "{dead:#?}");
    assert_eq!(
        crate::metrics::classify_sizes(&artifact).retained_bytes,
        None
    );
}

/// The ELF backend records an external import for a relocation whose local
/// symbol it did not collect as well as for a genuinely external one, so it
/// may not be read as proof that no local edge is missing.
#[test]
fn an_external_call_target_keeps_reachability_sizes_unavailable() {
    let artifact = ElfBackend
        .parse(&undefined_target_call_fixture())
        .expect("external call fixture parses");

    assert_eq!(
        artifact.calls[0].unresolved,
        Some(UnresolvedCall::ExternalImport)
    );
    let sizes = crate::metrics::classify_sizes(&artifact);
    assert_eq!(sizes.retained_bytes, None);
    assert_eq!(sizes.shared_dependency_bytes, None);
    assert!(crate::metrics::retained_sizes(&artifact).is_none());
    assert!(
        sizes.assumptions.iter().any(|assumption| assumption
            .contains("need every dispatch that may reach a local symbol to be resolved")),
        "{:?}",
        sizes.assumptions
    );
    let dead =
        crate::metrics::dead_code_candidates(&artifact).expect("an export establishes roots");
    assert!(!dead.definitive);
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
