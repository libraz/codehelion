//! Static archive implementation of the codehelion artifact backend boundary.
//!
//! An archive is not treated as one executable byte stream. Each local object
//! member is parsed by its format backend, then flattened only for common
//! metrics while retaining member provenance in [`ArtifactIr::archive_members`].

use std::collections::BTreeMap;

use crate::elf::ElfBackend;
use crate::macho::MachOBackend;
use crate::pe::PeCoffBackend;
use crate::support::format_support;
use crate::wasm::WasmBackend;
use crate::{
    ArtifactArchiveMember, ArtifactBackend, ArtifactCapabilities, ArtifactError,
    ArtifactFingerprint, ArtifactFormat, ArtifactIr, UnresolvedCall, detect_format,
};
use object::read::archive::ArchiveFile;

/// Parser backend for static archives containing locally embedded object files.
#[derive(Debug, Default, Clone, Copy)]
pub struct ArchiveBackend;

/// First position a member header can occupy, past the archive magic.
///
/// Both flavours this backend claims start with an eight-byte magic. Special
/// members the reader consumes on its own never become member facts of this
/// IR, so an unreadable member found before any member was read is reported
/// from here rather than from a position this backend never observed.
const MEMBER_REGION_START: u64 = 8;

impl ArtifactBackend for ArchiveBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Archive
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"!<arch>\n") || bytes.starts_with(b"!<thin>\n")
    }

    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
        // The reader below also accepts archive flavours this backend does not
        // claim. Without this guard a caller trying backends in turn would see
        // input of another format reported as a broken archive, and would stop
        // instead of offering it to the backend that owns it.
        if !self.detects(bytes) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::Archive,
            });
        }
        let archive = ArchiveFile::parse(bytes).map_err(|error| malformed(error.to_string()))?;
        let mut ir = ArtifactIr::empty(ArtifactFormat::Archive, bytes);
        let observed_bytes = ir.observed_bytes;
        // Where the next member header begins, advanced only by members the
        // container demonstrably holds. A member header that does not parse
        // has no position of its own, so this is the last position about this
        // archive that was actually observed.
        let mut next_header = MEMBER_REGION_START;
        for member in archive.members() {
            let member = match member {
                Ok(member) => member,
                Err(error) => {
                    // The unreadable bytes run from the last observed position
                    // to the end of the input. Recording that span keeps the
                    // record measured, where a member at the end of the
                    // archive would name a position no member occupies and a
                    // zero length that was never anyone's size.
                    ir.archive_members.push(incomplete_member(
                        "<truncated archive member>".to_owned(),
                        next_header,
                        observed_bytes.saturating_sub(next_header),
                        &error.to_string(),
                    ));
                    break;
                }
            };
            let name = String::from_utf8_lossy(member.name()).into_owned();
            let (offset, size) = member.file_range();
            let thin = member.is_thin();
            if !thin {
                // Member data is padded to an even boundary, so a member whose
                // range the input holds in full establishes where the header
                // after it begins. A declared range running past the end
                // establishes nothing, and thin members hold no local bytes.
                let end = offset.saturating_add(size);
                if end <= observed_bytes {
                    next_header = end.saturating_add(end % 2).min(observed_bytes);
                }
            }
            let data = match member.data(bytes) {
                Ok(data) => data,
                Err(error) => {
                    ir.archive_members.push(incomplete_member(
                        name,
                        offset,
                        size,
                        &error.to_string(),
                    ));
                    continue;
                }
            };
            let fingerprint = if thin {
                // Thin members deliberately have no local payload. Their
                // declared member paths are still distinct local evidence,
                // unlike hashing the same empty byte slice for every member.
                ArtifactFingerprint::from_content("thin-archive-member", name.as_bytes())
            } else {
                ArtifactFingerprint::from_content("archive-member", data)
            };
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
            debug_info_unreadable: ir.capabilities.debug_info_unreadable,
            // A normalizer belongs to an instruction architecture, so this is
            // the union the members' own backends declared. Counting decoded
            // symbols instead would let one member whose text failed to decode
            // withdraw the normalized figures of every other member, which the
            // same objects report when they are analysed outside the archive.
            normalized_duplicates: ir.capabilities.normalized_duplicates,
            independent_data_segments: false,
            relocations: !ir.relocations.is_empty(),
            data_segments: !ir.data_segments.is_empty(),
        };
        Ok(ir)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        format_support(ArtifactFormat::Archive).capabilities
    }
}

/// Record an unreadable archive member without discarding earlier members.
///
/// `offset` and `size` must be positions the parser observed: either the
/// member's declared range or the span from the last observed position to the
/// end of the input. Nothing about an unreadable member is inferred into them.
fn incomplete_member(name: String, offset: u64, size: u64, error: &str) -> ArtifactArchiveMember {
    let identity = format!("{name}:{offset}:{size}");
    ArtifactArchiveMember {
        name,
        fingerprint: ArtifactFingerprint::from_content(
            "archive-incomplete-member",
            identity.as_bytes(),
        ),
        offset,
        size,
        format: None,
        thin: false,
        parse_error: Some(format!("truncated or unreadable archive member: {error}")),
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
    archive.capabilities.debug_info_unreadable |= member.capabilities.debug_info_unreadable;
    archive.capabilities.normalized_duplicates |= member.capabilities.normalized_duplicates;
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
            if let Some(target) = call.target {
                call.target = fingerprints.get(&target).copied();
                // A target the member established but this merge could not
                // re-map is a lost edge. Recording why keeps it unresolved
                // evidence instead of a call that looks like it had no target.
                if call.target.is_none() {
                    call.unresolved = Some(UnresolvedCall::MissingRelocation);
                }
            }
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

/// This build's reader for the format, the input it parses, and the magic that
/// makes arbitrary bytes look like one of its own.
#[cfg(test)]
pub(crate) fn under_test() -> crate::FormatUnderTest {
    crate::FormatUnderTest {
        backend: &ArchiveBackend,
        valid: tests::archive_fixture(),
        magics: &[b"!<arch>\n", b"!<thin>\n"],
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

    fn coff_member(name: &[u8]) -> Vec<u8> {
        coff_member_with_code(name, &[0x90, 0xc3])
    }

    fn coff_member_with_code(name: &[u8], code: &[u8]) -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Coff, Architecture::X86_64, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        let offset = object.append_section_data(text, code, 1);
        object.add_symbol(Symbol {
            name: name.to_vec(),
            value: offset,
            size: code.len() as u64,
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
        if !bytes.len().is_multiple_of(2) {
            member.push(b'\n');
        }
        member
    }

    pub(super) fn archive_fixture() -> Vec<u8> {
        let first = coff_member(b"left");
        let second = coff_member(b"right");
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend(archive_member("left.obj", &first));
        archive.extend(archive_member("right.obj", &second));
        archive
    }

    /// An archive whose trailing member header stops mid-write, which is what
    /// an interrupted build or a partial download leaves behind. The returned
    /// position is where that header begins.
    fn archive_cut_inside_a_member_header() -> (Vec<u8>, u64) {
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend(archive_member("left.obj", &coff_member(b"left")));
        let header_start = archive.len() as u64;
        let second = archive_member("right.obj", &coff_member(b"right"));
        // Part of a member header is not a member header.
        archive.extend(&second[..20]);
        (archive, header_start)
    }

    fn thin_archive_fixture() -> Vec<u8> {
        let mut archive = b"!<thin>\n".to_vec();
        archive.extend(archive_member("left.obj", b""));
        archive.extend(archive_member("right.obj", b""));
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
    fn a_truncated_later_member_keeps_the_earlier_members_available() {
        let mut bytes = archive_fixture();
        bytes.truncate(bytes.len().saturating_sub(1));

        let ir = ArchiveBackend
            .parse(&bytes)
            .expect("a readable archive prefix remains useful");
        assert!(
            ir.archive_members
                .iter()
                .any(|member| member.name == "left.obj" && member.parse_error.is_none()),
            "the complete leading member remains available: {:#?}",
            ir.archive_members
        );
        assert!(
            ir.archive_members.iter().any(|member| {
                member
                    .parse_error
                    .as_deref()
                    .is_some_and(|error| error.contains("truncated or unreadable"))
            }),
            "the unreadable tail is accounted for: {:#?}",
            ir.archive_members
        );
    }

    /// An unreadable member has no position of its own, so the record for it
    /// carries the span the parser could not read: it starts where the parser
    /// stopped, never at the end of the archive, and its length is the extent
    /// of that span rather than a zero that reads as a measured size.
    #[test]
    fn an_unreadable_member_is_recorded_at_the_position_the_parser_reached() {
        let (bytes, header_start) = archive_cut_inside_a_member_header();

        let ir = ArchiveBackend
            .parse(&bytes)
            .expect("a readable archive prefix remains useful");
        assert!(
            ir.archive_members
                .iter()
                .any(|member| member.name == "left.obj" && member.parse_error.is_none()),
            "the complete leading member remains available: {:#?}",
            ir.archive_members
        );
        let incomplete = unreadable_member(&ir);
        assert_eq!(
            incomplete.offset, header_start,
            "the record starts where the parser stopped: {:#?}",
            ir.archive_members
        );
        assert_ne!(
            incomplete.offset, ir.observed_bytes,
            "no member begins at the end of the archive: {:#?}",
            ir.archive_members
        );
        assert_eq!(
            incomplete.size,
            ir.observed_bytes - header_start,
            "the unread span is measured, not reported as empty: {:#?}",
            ir.archive_members
        );
    }

    /// Thin members hold no local bytes, so no member before the failure
    /// established a position. The span then reaches back to the first
    /// position a member header can occupy, which is still observed.
    #[test]
    fn an_unreadable_thin_member_spans_the_archive_from_its_member_region() {
        let mut bytes = b"!<thin>\n".to_vec();
        bytes.extend(archive_member("left.obj", b""));
        bytes.extend(&archive_member("right.obj", b"")[..20]);

        let ir = ArchiveBackend
            .parse(&bytes)
            .expect("a readable thin manifest prefix remains useful");
        let incomplete = unreadable_member(&ir);
        assert_eq!(incomplete.offset, MEMBER_REGION_START, "{ir:#?}");
        assert_eq!(
            incomplete.size,
            ir.observed_bytes - MEMBER_REGION_START,
            "{ir:#?}"
        );
    }

    fn unreadable_member(ir: &ArtifactIr) -> &ArtifactArchiveMember {
        ir.archive_members
            .iter()
            .find(|member| {
                member
                    .parse_error
                    .as_deref()
                    .is_some_and(|error| error.contains("truncated or unreadable"))
            })
            .expect("the unreadable bytes are accounted for")
    }

    #[test]
    fn thin_members_keep_distinct_path_based_fingerprints() {
        let ir = ArchiveBackend
            .parse(&thin_archive_fixture())
            .expect("parse thin archive manifest");
        assert_eq!(ir.archive_members.len(), 2, "{ir:#?}");
        assert!(ir.archive_members.iter().all(|member| member.thin));
        assert_ne!(
            ir.archive_members[0].fingerprint,
            ir.archive_members[1].fingerprint
        );
    }

    /// A normalizer belongs to an instruction architecture, so one member
    /// whose text does not decode cannot withdraw the normalized figures the
    /// other members support. The same objects report those figures when they
    /// are analysed outside the archive.
    #[test]
    fn an_undecodable_member_keeps_the_other_members_normalized_duplicates() {
        let mut archive = b"!<arch>\n".to_vec();
        // Two bodies that differ only in an immediate, which is exactly the
        // duplication normalization exists to see.
        archive.extend(archive_member(
            "left.obj",
            &coff_member_with_code(b"left", &[0xb8, 1, 0, 0, 0, 0xc3]),
        ));
        archive.extend(archive_member(
            "right.obj",
            &coff_member_with_code(b"right", &[0xb8, 2, 0, 0, 0, 0xc3]),
        ));
        // A lone escape byte is not a complete instruction.
        archive.extend(archive_member(
            "opaque.obj",
            &coff_member_with_code(b"opaque", &[0x0f]),
        ));

        let ir = ArchiveBackend.parse(&archive).expect("parse mixed archive");

        assert_eq!(ir.symbols.len(), 3, "{ir:#?}");
        assert!(
            ir.symbols.iter().any(|symbol| symbol.normalized.is_none()),
            "the fixture must contain a symbol that does not decode: {ir:#?}"
        );
        assert!(
            ir.capabilities.normalized_duplicates,
            "{:?}",
            ir.capabilities
        );
        let sizes = crate::metrics::classify_sizes(&ir);
        assert_eq!(sizes.duplicated_bytes, 0, "{sizes:#?}");
        assert_eq!(sizes.duplicated_bytes_normalized, Some(6), "{sizes:#?}");
        assert!(
            !sizes
                .assumptions
                .iter()
                .any(|assumption| assumption.contains("needs a normalizer for this architecture")),
            "{:?}",
            sizes.assumptions
        );
    }

    /// The same objects outside an archive establish the same capability, so
    /// being read inside one changes no architecture fact.
    #[test]
    fn membership_of_an_archive_does_not_change_a_normalizer_fact() {
        let member = coff_member_with_code(b"left", &[0xb8, 1, 0, 0, 0, 0xc3]);
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend(archive_member("left.obj", &member));

        let alone = PeCoffBackend
            .parse(&member)
            .expect("parse the object alone");
        let inside = ArchiveBackend.parse(&archive).expect("parse the archive");

        assert_eq!(
            inside.capabilities.normalized_duplicates,
            alone.capabilities.normalized_duplicates
        );
        assert!(inside.capabilities.normalized_duplicates);
    }

    /// A caller chaining backends learns "not mine", not "mine and broken".
    #[test]
    fn other_bytes_do_not_claim_the_backend() {
        let elf = {
            let mut object =
                WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
            let text = object.section_id(StandardSection::Text);
            object.append_section_data(text, &[0x90, 0xc3], 1);
            object.write().expect("write ELF object")
        };
        for other in [
            b"not an archive".as_slice(),
            elf.as_slice(),
            // An archive flavour with its own member layout, which this
            // backend does not read.
            b"<bigaf>\n".as_slice(),
            b"".as_slice(),
        ] {
            assert!(!ArchiveBackend.detects(other));
            assert!(
                matches!(
                    ArchiveBackend.parse(other),
                    Err(ArtifactError::WrongFormat {
                        expected: ArtifactFormat::Archive
                    })
                ),
                "{:02x?}",
                &other[..other.len().min(16)]
            );
        }
    }

    /// Everything the backend claims is answered by the archive reader itself.
    #[test]
    fn claimed_bytes_are_never_answered_with_another_format() {
        for claimed in [
            archive_fixture(),
            thin_archive_fixture(),
            b"!<arch>\n".to_vec(),
            b"!<thin>\njunk".to_vec(),
        ] {
            assert!(ArchiveBackend.detects(&claimed));
            assert!(
                !matches!(
                    ArchiveBackend.parse(&claimed),
                    Err(ArtifactError::WrongFormat { .. } | ArtifactError::Unsupported { .. })
                ),
                "{:02x?}",
                &claimed[..claimed.len().min(16)]
            );
        }
    }

    /// Changed member bytes still travel member iteration and delegation.
    ///
    /// Generated input is only worth anything if it gets past the archive
    /// magic, so this pins the reachability the property test below relies on:
    /// the altered instruction comes back out of a delegated member parse.
    #[test]
    fn an_altered_member_is_read_through_member_iteration_and_delegation() {
        let mut bytes = archive_fixture();
        let position = bytes
            .windows(2)
            .position(|window| window == [0x90, 0xc3])
            .expect("fixture carries its member instruction bytes");
        bytes[position] = 0x50;

        let ir = ArchiveBackend
            .parse(&bytes)
            .expect("altered fixture parses");
        assert_eq!(ir.archive_members.len(), 2, "{ir:#?}");
        assert_eq!(ir.symbols.len(), 2, "{ir:#?}");
        assert!(
            ir.symbols.iter().any(|symbol| symbol.code == [0x50, 0xc3]),
            "{ir:#?}"
        );
        assert!(
            ir.symbols
                .iter()
                .all(|symbol| symbol.normalized.is_some() && !symbol.code.is_empty()),
            "{ir:#?}"
        );
    }
}
