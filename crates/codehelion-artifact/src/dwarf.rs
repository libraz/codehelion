//! Format-neutral DWARF source-location extraction for artifact backends.

use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;

use gimli::{DwarfSections, EndianSlice, Reader, RunTimeEndian};
use object::{Endianness, Object, ObjectSection};

use crate::{ArtifactFingerprint, ArtifactInlineFrame, ArtifactIr, ArtifactSourceMapping};

/// Attach optional DWARF locations to parser-established symbol identities.
///
/// Malformed or absent debug metadata deliberately degrades to no mappings.
/// Addresses are used only for the local join and are never stored as IDs.
pub fn attach_dwarf_frames<S: BuildHasher>(
    file: &object::File<'_>,
    symbol_addresses: &HashMap<ArtifactFingerprint, (u64, u64), S>,
    ir: &mut ArtifactIr,
) {
    let endian = match file.endianness() {
        Endianness::Little => RunTimeEndian::Little,
        Endianness::Big => RunTimeEndian::Big,
    };
    let Ok(sections) = DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            debug_section(file, id.name())
                .and_then(|section| section.data().ok())
                .unwrap_or_default()
                .to_vec(),
        )
    }) else {
        return;
    };
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
    let mut frames = Vec::new();
    let mut line_records = Vec::new();
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        let mut depth = 0isize;
        while let Ok(Some((delta, entry))) = entries.next_dfs() {
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
                continue;
            };
            while let Ok(Some(range)) = ranges.next() {
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
        line_records.extend(line_frames(&dwarf, &unit));
    }
    if frames.is_empty() && line_records.is_empty() {
        return;
    }
    let mut source_paths = BTreeSet::new();
    for (fingerprint, (address, size)) in symbol_addresses {
        let mut matching: Vec<_> = frames
            .iter()
            .filter(|candidate| candidate.begin <= *address && *address < candidate.end)
            .map(|candidate| (candidate.depth, candidate.frame.clone()))
            .collect();
        let symbol_end = address.saturating_add(*size);
        matching.extend(
            line_records
                .iter()
                .filter(|candidate| *address <= candidate.address && candidate.address < symbol_end)
                .map(|candidate| (isize::MAX, candidate.frame.clone())),
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
        if let Some(symbol) = ir
            .symbols
            .iter_mut()
            .find(|symbol| symbol.fingerprint == *fingerprint)
        {
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
    frame: ArtifactInlineFrame,
}

fn line_frames<R: Reader>(dwarf: &gimli::Dwarf<R>, unit: &gimli::Unit<R>) -> Vec<DwarfLineFrame> {
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
        frames.push(DwarfLineFrame {
            address: row.address(),
            frame: ArtifactInlineFrame {
                evidence_kind: crate::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: resolve_source_path(
                    &source,
                    directory.as_deref(),
                    compilation_directory.as_deref(),
                ),
                line: Some(line),
                column,
            },
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
