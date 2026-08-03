//! Format-neutral DWARF source-location extraction for artifact backends.

use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;

use gimli::{DwarfSections, EndianSlice, Reader, RunTimeEndian};
use object::{Endianness, Object, ObjectKind, ObjectSection};

use crate::{ArtifactFingerprint, ArtifactInlineFrame, ArtifactIr, ArtifactSourceMapping};

const MAX_DWARF_DEBUG_BYTES: u64 = 64 * 1024 * 1024;

/// Attach optional DWARF locations to parser-established symbol identities.
///
/// Malformed or absent debug metadata deliberately degrades to no mappings.
/// Addresses are used only for the local join and are never stored as IDs.
#[allow(
    clippy::too_many_lines,
    reason = "DWARF collection and the local address-to-symbol join form one parser boundary"
)]
pub fn attach_dwarf_frames<S: BuildHasher>(
    file: &object::File<'_>,
    symbol_addresses: &HashMap<ArtifactFingerprint, (u64, u64), S>,
    ir: &mut ArtifactIr,
) {
    if !supports_address_join(file.kind()) {
        return;
    }
    let endian = match file.endianness() {
        Endianness::Little => RunTimeEndian::Little,
        Endianness::Big => RunTimeEndian::Big,
    };
    let mut remaining_debug_bytes = MAX_DWARF_DEBUG_BYTES;
    let mut debug_info_unreadable = false;
    let Ok(sections) = DwarfSections::load(|id| {
        let Some(section) = debug_section(file, id.name()) else {
            return Ok::<_, gimli::Error>(Vec::new());
        };
        let Ok(data) = section.compressed_data() else {
            debug_info_unreadable = true;
            return Ok(Vec::new());
        };
        if data.uncompressed_size > remaining_debug_bytes {
            debug_info_unreadable = true;
            return Ok(Vec::new());
        }
        let Ok(data) = data.decompress() else {
            debug_info_unreadable = true;
            return Ok(Vec::new());
        };
        remaining_debug_bytes -= data.len() as u64;
        Ok(data.into_owned())
    }) else {
        return;
    };
    ir.capabilities.debug_info_unreadable |= debug_info_unreadable;
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
    let mut frames = Vec::new();
    let mut line_records = Vec::new();
    let mut line_paths = DwarfPathInterner::default();
    let mut units = dwarf.units();
    loop {
        let header = match units.next() {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(_) => {
                ir.capabilities.debug_info_unreadable = true;
                break;
            }
        };
        let Ok(unit) = dwarf.unit(header) else {
            ir.capabilities.debug_info_unreadable = true;
            continue;
        };
        let mut entries = unit.entries();
        let mut depth = 0isize;
        loop {
            let entry = match entries.next_dfs() {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(_) => {
                    ir.capabilities.debug_info_unreadable = true;
                    break;
                }
            };
            let (delta, entry) = entry;
            depth += delta;
            if !matches!(
                entry.tag(),
                gimli::DW_TAG_subprogram | gimli::DW_TAG_inlined_subroutine
            ) {
                continue;
            }
            let Some(frame) = source_frame(&dwarf, &unit, entry) else {
                continue;
            };
            let Ok(mut ranges) = dwarf.die_ranges(&unit, entry) else {
                ir.capabilities.debug_info_unreadable = true;
                continue;
            };
            loop {
                let range = match ranges.next() {
                    Ok(Some(range)) => range,
                    Ok(None) => break,
                    Err(_) => {
                        ir.capabilities.debug_info_unreadable = true;
                        break;
                    }
                };
                if range.begin < range.end {
                    frames.push(DwarfFrame {
                        begin: range.begin,
                        end: range.end,
                        depth,
                        frame: frame.clone(),
                    });
                }
            }
        }
        line_records.extend(line_frames(&dwarf, &unit, &mut line_paths));
    }
    if frames.is_empty() && line_records.is_empty() {
        return;
    }
    frames.sort_by_key(|frame| frame.begin);
    line_records.sort_by_key(|frame| frame.address);
    let mut symbols: Vec<_> = symbol_addresses
        .iter()
        .map(|(fingerprint, (address, size))| (*fingerprint, *address, *size))
        .collect();
    symbols.sort_by_key(|(_, address, _)| *address);
    let frame_matches = frames_at_symbol_addresses(&frames, &symbols);
    let symbol_rows: HashMap<_, _> = ir
        .symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| (symbol.fingerprint, index))
        .collect();
    let mut source_paths = BTreeSet::new();
    for ((fingerprint, address, size), frame_indexes) in symbols.into_iter().zip(frame_matches) {
        let mut matching: Vec<_> = frame_indexes
            .into_iter()
            .map(|index| (frames[index].depth, frames[index].frame.clone()))
            .collect();
        let symbol_end = address.saturating_add(size);
        let line_start = line_records.partition_point(|candidate| candidate.address < address);
        matching.extend(
            line_records
                .get(line_start..)
                .into_iter()
                .flatten()
                .take_while(|candidate| candidate.address < symbol_end)
                .map(|candidate| (isize::MAX, candidate.inline_frame(&line_paths))),
        );
        matching.sort_by(|left, right| {
            (&left.1.source, left.1.line, left.1.column, left.0).cmp(&(
                &right.1.source,
                right.1.line,
                right.1.column,
                right.0,
            ))
        });
        matching.dedup_by(|left, right| left.1 == right.1);
        if matching.is_empty() {
            continue;
        }
        if let Some(index) = symbol_rows.get(&fingerprint) {
            let symbol = &mut ir.symbols[*index];
            symbol.inline_stack = matching.into_iter().map(|(_, frame)| frame).collect();
            source_paths.extend(symbol.inline_stack.iter().map(|frame| frame.source.clone()));
        }
    }
    ir.source_mappings.extend(
        source_paths
            .into_iter()
            .map(|uri| ArtifactSourceMapping { uri }),
    );
}

const fn supports_address_join(kind: ObjectKind) -> bool {
    !matches!(kind, ObjectKind::Relocatable)
}

fn frames_at_symbol_addresses(
    frames: &[DwarfFrame],
    symbols: &[(ArtifactFingerprint, u64, u64)],
) -> Vec<Vec<usize>> {
    let mut active = BTreeSet::new();
    let mut next = 0;
    symbols
        .iter()
        .map(|(_, address, _)| {
            while next < frames.len() && frames[next].begin <= *address {
                active.insert((frames[next].end, next));
                next += 1;
            }
            while active.first().is_some_and(|(end, _)| *end <= *address) {
                let _ = active.pop_first();
            }
            active.iter().map(|(_, index)| *index).collect()
        })
        .collect()
}

fn debug_section<'data, 'file>(
    file: &'file object::File<'data>,
    name: &str,
) -> Option<object::Section<'data, 'file>> {
    file.section_by_name(name).or_else(|| {
        let macho_name: String = format!("__{}", name.trim_start_matches('.'))
            .chars()
            .take(16)
            .collect();
        file.section_by_name(&macho_name)
    })
}

#[derive(Debug, Clone)]
struct DwarfFrame {
    begin: u64,
    end: u64,
    depth: isize,
    frame: ArtifactInlineFrame,
}

#[derive(Debug, Clone)]
struct DwarfLineFrame {
    address: u64,
    source: u32,
    line: u32,
    /// Zero represents DWARF's left-edge position without a numeric column.
    column: u32,
}

impl DwarfLineFrame {
    fn inline_frame(&self, paths: &DwarfPathInterner) -> ArtifactInlineFrame {
        ArtifactInlineFrame {
            evidence_kind: crate::ArtifactSourceLocationEvidenceKind::Dwarf,
            source: paths.get(self.source).to_owned(),
            line: Some(self.line),
            column: (self.column != 0).then_some(self.column),
        }
    }
}

/// Deduplicate resolved source paths while retaining compact line records.
#[derive(Debug, Default)]
struct DwarfPathInterner {
    indexes: HashMap<String, usize>,
    values: Vec<String>,
}

impl DwarfPathInterner {
    fn intern(&mut self, path: String) -> Option<u32> {
        if let Some(index) = self.indexes.get(&path) {
            return u32::try_from(*index).ok();
        }
        let index = self.values.len();
        let index = u32::try_from(index).ok()?;
        self.values.push(path.clone());
        self.indexes.insert(path, index as usize);
        Some(index)
    }

    fn get(&self, index: u32) -> &str {
        self.values
            .get(index as usize)
            .map_or("<invalid-dwarf-path>", String::as_str)
    }
}

fn line_frames<R: Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    paths: &mut DwarfPathInterner,
) -> Vec<DwarfLineFrame> {
    let Some(program) = unit.line_program.clone() else {
        return Vec::new();
    };
    let compilation_directory = unit.comp_dir.as_ref().and_then(reader_string);
    let mut rows = program.rows();
    let mut frames = Vec::new();
    while let Ok(Some((header, row))) = rows.next_row() {
        if row.end_sequence() {
            continue;
        }
        let Some(line) = row.line().and_then(|value| u32::try_from(value.get()).ok()) else {
            continue;
        };
        let Some(file) = row.file(header) else {
            continue;
        };
        let Some(source) = dwarf
            .attr_string(unit, file.path_name())
            .ok()
            .and_then(|value| reader_string(&value))
        else {
            continue;
        };
        let directory = file
            .directory(header)
            .and_then(|value| dwarf.attr_string(unit, value).ok())
            .and_then(|value| reader_string(&value));
        let column = match row.column() {
            gimli::ColumnType::LeftEdge => None,
            gimli::ColumnType::Column(value) => u32::try_from(value.get()).ok(),
        };
        let Some(source) = paths.intern(resolve_source_path(
            &source,
            directory.as_deref(),
            compilation_directory.as_deref(),
        )) else {
            continue;
        };
        frames.push(DwarfLineFrame {
            address: row.address(),
            source,
            line,
            column: column.unwrap_or(0),
        });
    }
    frames
}

fn source_frame<R: Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R>,
) -> Option<ArtifactInlineFrame> {
    let attributes = if entry.tag() == gimli::DW_TAG_inlined_subroutine {
        (
            gimli::DW_AT_call_file,
            gimli::DW_AT_call_line,
            gimli::DW_AT_call_column,
        )
    } else {
        (
            gimli::DW_AT_decl_file,
            gimli::DW_AT_decl_line,
            gimli::DW_AT_decl_column,
        )
    };
    let file_index = entry
        .attr_value(attributes.0)
        .ok()
        .flatten()
        .and_then(|value| value.udata_value())?;
    let line_program = unit.line_program.as_ref()?;
    let file = line_program.header().file(file_index)?;
    let source = dwarf
        .attr_string(unit, file.path_name())
        .ok()
        .and_then(|value| reader_string(&value))?;
    let directory = file
        .directory(line_program.header())
        .and_then(|value| dwarf.attr_string(unit, value).ok())
        .and_then(|value| reader_string(&value));
    let compilation_directory = unit.comp_dir.as_ref().and_then(reader_string);
    let line = entry
        .attr_value(attributes.1)
        .ok()
        .flatten()
        .and_then(|value| value.udata_value())
        .and_then(|value| u32::try_from(value).ok());
    let column = entry
        .attr_value(attributes.2)
        .ok()
        .flatten()
        .and_then(|value| value.udata_value())
        .and_then(|value| u32::try_from(value).ok());
    Some(ArtifactInlineFrame {
        evidence_kind: crate::ArtifactSourceLocationEvidenceKind::Dwarf,
        source: resolve_source_path(
            &source,
            directory.as_deref(),
            compilation_directory.as_deref(),
        ),
        line,
        column,
    })
}

fn reader_string<R: Reader>(value: &R) -> Option<String> {
    value
        .to_string_lossy()
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// Resolve a DWARF path as metadata, without opening the declared source file.
#[must_use]
pub fn resolve_source_path(
    file: &str,
    directory: Option<&str>,
    compilation_directory: Option<&str>,
) -> String {
    fn rooted(path: &str) -> bool {
        path.starts_with('/')
    }
    fn under(base: &str, path: &str) -> String {
        format!("{}/{path}", base.trim_end_matches('/'))
    }
    if rooted(file) {
        return file.to_string();
    }
    let base = match directory {
        Some(directory) if rooted(directory) => Some(directory.to_string()),
        Some(directory) => compilation_directory.map(|root| under(root, directory)),
        None => compilation_directory.map(ToString::to_string),
    };
    base.map_or_else(|| file.to_string(), |base| under(&base, file))
}

#[cfg(test)]
mod tests {
    use super::{
        DwarfFrame, DwarfLineFrame, DwarfPathInterner, debug_section, frames_at_symbol_addresses,
        resolve_source_path, supports_address_join,
    };
    use crate::{ArtifactFingerprint, ArtifactInlineFrame, ArtifactSourceLocationEvidenceKind};
    use object::ObjectKind;

    fn frame(begin: u64, end: u64) -> DwarfFrame {
        DwarfFrame {
            begin,
            end,
            depth: 0,
            frame: ArtifactInlineFrame {
                evidence_kind: ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "fixture.rs".to_owned(),
                line: Some(1),
                column: None,
            },
        }
    }

    #[test]
    fn frame_join_advances_a_sweep_index_without_rescanning_all_frames() {
        let frames = [frame(10, 30), frame(20, 25), frame(40, 50)];
        let symbols = [
            (ArtifactFingerprint::from_content("test", b"first"), 12, 4),
            (ArtifactFingerprint::from_content("test", b"second"), 22, 2),
            (ArtifactFingerprint::from_content("test", b"third"), 45, 3),
        ];
        assert_eq!(
            frames_at_symbol_addresses(&frames, &symbols),
            vec![vec![0], vec![1, 0], vec![2]]
        );
    }

    #[test]
    fn relocatable_objects_reject_address_only_dwarf_joins() {
        assert!(!supports_address_join(ObjectKind::Relocatable));
        assert!(supports_address_join(ObjectKind::Executable));
        assert!(supports_address_join(ObjectKind::Dynamic));
    }

    #[test]
    fn relative_paths_keep_their_declared_directory_context_without_reading_source() {
        assert_eq!(
            resolve_source_path("src/main.cpp", None, Some("/work/tree")),
            "/work/tree/src/main.cpp"
        );
        assert_eq!(
            resolve_source_path("header.hpp", Some("include"), Some("/work/tree")),
            "/work/tree/include/header.hpp"
        );
        assert_eq!(
            resolve_source_path("entry.cpp", Some("/other/build"), Some("/work/tree")),
            "/other/build/entry.cpp"
        );
        assert_eq!(
            resolve_source_path("/outside/entry.cpp", Some("include"), Some("/work/tree")),
            "/outside/entry.cpp"
        );
        assert_eq!(
            resolve_source_path("src/main.cpp", None, Some("/work/tree/")),
            "/work/tree/src/main.cpp"
        );
        assert_eq!(
            resolve_source_path("header.hpp", Some("include/"), Some("/work/tree/")),
            "/work/tree/include/header.hpp"
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn line_records_intern_repeated_paths_until_they_are_attached_to_symbols() {
        let mut paths = DwarfPathInterner::default();
        let first = paths.intern("/work/src/lib.rs".to_owned()).unwrap();
        let second = paths.intern("/work/src/lib.rs".to_owned()).unwrap();
        let frame = DwarfLineFrame {
            address: 12,
            source: first,
            line: 5,
            column: 0,
        };

        assert_eq!(first, second);
        assert_eq!(paths.values.len(), 1);
        assert_eq!(frame.inline_frame(&paths).source, "/work/src/lib.rs");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn compressed_legacy_debug_sections_are_found_and_decompressed() {
        use std::io::Write;

        use flate2::{Compression, write::ZlibEncoder};
        use object::write::{Object as WriteObject, StandardSegment};
        use object::{Architecture, BinaryFormat, Endianness, ObjectSection, SectionKind};

        let payload = b"compressed dwarf fixture";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut section_data = b"ZLIB".to_vec();
        section_data.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        section_data.extend_from_slice(&compressed);

        let mut writer =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let section = writer.add_section(
            writer.segment_name(StandardSegment::Debug).to_vec(),
            b".zdebug_info".to_vec(),
            SectionKind::Debug,
        );
        writer.append_section_data(section, &section_data, 1);
        let bytes = writer.write().unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let section = debug_section(&file, ".debug_info").unwrap();

        assert_eq!(section.uncompressed_data().unwrap().as_ref(), payload);
    }
}
