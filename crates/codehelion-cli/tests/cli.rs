//! End-to-end tests that run the compiled binary.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;
use fs2::FileExt;
use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use predicates::prelude::*;
use std::fs::OpenOptions;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A temporary directory, spelled the way the commands under test spell it.
///
/// [`std::fs::canonicalize`] answers a Windows path in the verbatim `\\?\`
/// form. No command prints that form: each resolves the path it was given
/// through [`codehelion_core::paths::canonical`], which drops the prefix
/// wherever the ordinary spelling names the same file. A fixture built from
/// the other form therefore expects a path that appears in no output, and the
/// test fails on Windows for a reason that has nothing to do with what it is
/// checking.
fn resolved_root(directory: &tempfile::TempDir) -> std::path::PathBuf {
    codehelion_core::paths::canonical(directory.path()).expect("resolve temp dir")
}

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

#[path = "cli/artifact.rs"]
mod artifact;
#[path = "cli/cache.rs"]
mod cache;
#[path = "cli/config.rs"]
mod config;
#[path = "cli/database_schema.rs"]
mod database_schema;
#[path = "cli/docs_wording.rs"]
mod docs_wording;
#[path = "cli/doctor.rs"]
mod doctor;
#[path = "cli/help_and_arguments.rs"]
mod help_and_arguments;
#[path = "cli/scan_command.rs"]
mod scan_command;
