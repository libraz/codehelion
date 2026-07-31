//! Static archive implementation of the codehelion artifact backend boundary.
//!
//! An archive is not treated as one executable byte stream. Each local object
//! member is parsed by its format backend, then flattened only for common
//! metrics while retaining member provenance in [`ArtifactIr::archive_members`].

use std::collections::BTreeMap;

use codehelion_artifact::{
    ArtifactArchiveMember, ArtifactBackend, ArtifactCapabilities, ArtifactError,
    ArtifactFingerprint, ArtifactFormat, ArtifactIr, detect_format,
};
use codehelion_artifact_elf::ElfBackend;
use codehelion_artifact_macho::MachOBackend;
use codehelion_artifact_pe::PeCoffBackend;
use codehelion_artifact_wasm::WasmBackend;
use object::read::archive::ArchiveFile;

/// Parser backend for static archives containing locally embedded object files.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArchiveBackend;

impl ArtifactBackend for ArchiveBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Archive
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"!<arch>\n") || bytes.starts_with(b"!<thin>\n")
    }

    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
        let archive = ArchiveFile::parse(bytes).map_err(|error| malformed(error.to_string()))?;
        let mut ir = ArtifactIr::empty(ArtifactFormat::Archive, bytes);
        for member in archive.members() {
            let member = member.map_err(|error| malformed(error.to_string()))?;
            let name = String::from_utf8_lossy(member.name()).into_owned();
            let (offset, size) = member.file_range();
            let thin = member.is_thin();
            let data = member
                .data(bytes)
                .map_err(|error| malformed(error.to_string()))?;
            let fingerprint = ArtifactFingerprint::from_content("archive-member", data);
            let format = detect_format(data);
            let mut provenance = ArtifactArchiveMember {
                name,
                fingerprint,
                offset,
                size,
                format,
                thin,
                parse_error: None,
            };
            if thin {
                provenance.parse_error = Some(
                    "thin archive member has no local bytes; external paths are never followed"
                        .to_owned(),
                );
            } else if let Some(format) = format {
                match parse_member(format, data) {
                    Ok(member_ir) => merge_member(&mut ir, member_ir, &provenance),
                    Err(error) => provenance.parse_error = Some(error.to_string()),
                }
            } else {
                provenance.parse_error = Some("member format is not supported".to_owned());
            }
            ir.archive_members.push(provenance);
        }
        ir.capabilities = ArtifactCapabilities {
            symbols: !ir.symbols.is_empty(),
            call_graph: !ir.calls.is_empty(),
            source_mapping: !ir.source_mappings.is_empty(),
            relocations: !ir.relocations.is_empty(),
            data_segments: !ir.data_segments.is_empty(),
        };
        Ok(ir)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        ArtifactCapabilities {
            symbols: true,
            call_graph: true,
            source_mapping: true,
            relocations: true,
            data_segments: true,
        }
    }
}

fn parse_member(format: ArtifactFormat, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
    match format {
        ArtifactFormat::Wasm => WasmBackend.parse(bytes),
        ArtifactFormat::Elf => ElfBackend.parse(bytes),
        ArtifactFormat::MachO => MachOBackend.parse(bytes),
        ArtifactFormat::PeCoff => PeCoffBackend.parse(bytes),
        ArtifactFormat::Archive => Err(ArtifactError::Unsupported {
            format: ArtifactFormat::Archive,
        }),
    }
}

/// Merge a parsed local object without letting its local offsets act as IDs.
fn merge_member(archive: &mut ArtifactIr, member: ArtifactIr, provenance: &ArtifactArchiveMember) {
    let prefix = format!("{}:", provenance.name);
    archive
        .sections
        .extend(member.sections.into_iter().map(|mut section| {
            section.name = Some(format!("{prefix}{}", section.name.unwrap_or_default()));
            section.offset = provenance.offset.saturating_add(section.offset);
            section
        }));
    archive.imports.extend(member.imports);
    let mut fingerprints = BTreeMap::new();
    for mut symbol in member.symbols {
        let original = symbol.fingerprint;
        let fingerprint =
            archive_member_fingerprint("archive-symbol", provenance.fingerprint, original);
        fingerprints.insert(original, fingerprint);
        symbol.fingerprint = fingerprint;
        symbol.section = None;
        symbol.offset = provenance.offset.saturating_add(symbol.offset);
        archive.symbols.push(symbol);
    }
    archive.entry_points.extend(
        member
            .entry_points
            .into_iter()
            .filter_map(|value| fingerprints.get(&value).copied()),
    );
    archive.indirect_references.extend(
        member
            .indirect_references
            .into_iter()
            .filter_map(|value| fingerprints.get(&value).copied()),
    );
    archive
        .calls
        .extend(member.calls.into_iter().filter_map(|mut call| {
            let caller = fingerprints.get(&call.caller).copied()?;
            call.caller = caller;
            call.target = call
                .target
                .and_then(|target| fingerprints.get(&target).copied());
            Some(call)
        }));
    archive
        .relocations
        .extend(member.relocations.into_iter().map(|mut relocation| {
            relocation.section = None;
            relocation.offset = provenance.offset.saturating_add(relocation.offset);
            relocation
        }));
    archive.source_mappings.extend(member.source_mappings);
    archive
        .source_mappings
        .sort_by(|left, right| left.uri.cmp(&right.uri));
    archive.source_mappings.dedup();
    archive
        .data_segments
        .extend(member.data_segments.into_iter().map(|mut data| {
            data.fingerprint = archive_member_fingerprint(
                "archive-data",
                provenance.fingerprint,
                data.fingerprint,
            );
            data.section = None;
            data.offset = provenance.offset.saturating_add(data.offset);
            data
        }));
    archive.entry_points.sort();
    archive.entry_points.dedup();
    archive.indirect_references.sort();
    archive.indirect_references.dedup();
}

fn archive_member_fingerprint(
    domain: &str,
    member: ArtifactFingerprint,
    child: ArtifactFingerprint,
) -> ArtifactFingerprint {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend(member.as_bytes());
    bytes.extend(child.as_bytes());
    ArtifactFingerprint::from_content(domain, &bytes)
}

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::Archive,
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

    fn coff_member(name: &[u8]) -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        let offset = object.append_section_data(text, &[0x90, 0xc3], 1);
        object.add_symbol(Symbol {
            name: name.to_vec(),
            value: offset,
            size: 2,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        object.write().expect("write COFF member")
    }

    fn archive_member(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut member = Vec::new();
        let name = format!("{name}/");
        member.extend(format!("{name:<16}").as_bytes());
        member.extend(b"0           0     0     100644  ");
        member.extend(format!("{:<10}", bytes.len()).as_bytes());
        member.extend(b"`\n");
        member.extend(bytes);
        if bytes.len() % 2 != 0 {
            member.push(b'\n');
        }
        member
    }

    fn archive_fixture() -> Vec<u8> {
        let first = coff_member(b"left");
        let second = coff_member(b"right");
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend(archive_member("left.obj", &first));
        archive.extend(archive_member("right.obj", &second));
        archive
    }

    #[test]
    fn delegates_local_coff_members_without_executing_them() {
        let ir = ArchiveBackend
            .parse(&archive_fixture())
            .expect("parse archive fixture");
        assert_eq!(ir.format, ArtifactFormat::Archive);
        assert_eq!(ir.archive_members.len(), 2, "{ir:#?}");
        assert!(
            ir.archive_members
                .iter()
                .all(|member| member.parse_error.is_none())
        );
        assert_eq!(ir.symbols.len(), 2, "{ir:#?}");
        assert_ne!(ir.symbols[0].fingerprint, ir.symbols[1].fingerprint);
        assert!(ir.capabilities.symbols);
    }

    #[test]
    fn other_bytes_do_not_claim_the_backend() {
        assert!(!ArchiveBackend.detects(b"not an archive"));
        assert!(matches!(
            ArchiveBackend.parse(b"not an archive"),
            Err(ArtifactError::Malformed { .. })
        ));
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let _ = ArchiveBackend.parse(&bytes);
        }
    }
}
