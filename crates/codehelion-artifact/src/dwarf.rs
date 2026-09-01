//! Format-neutral DWARF source-location extraction for artifact backends.

use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;

use gimli::{DwarfSections, EndianSlice, Reader, RunTimeEndian};
use object::{Endianness, Object, ObjectKind, ObjectSection};

use crate::{ArtifactFingerprint, ArtifactInlineFrame, ArtifactIr, ArtifactSourceMapping};

const MAX_DWARF_DEBUG_BYTES: u64 = 64 * 1024 * 1024;

/// Bounds on every structure derived from accepted debug bytes.
///
/// Debug metadata describes address ranges and line-table rows far more
/// compactly than the structures a reader builds from them, so a byte budget on
/// the input alone leaves a small section free to expand into an unbounded
/// number of frames, index entries, and attached source locations. Each field
/// bounds one derived structure directly. Reaching a bound stops collection and
/// reports the debug information as not fully readable, keeping the mappings
/// established so far.
#[derive(Debug, Clone, Copy)]
pub struct DwarfBudget {
    /// Retained subprogram address ranges.
    frames: usize,
    /// Retained line-table rows.
    line_records: usize,
    /// Frame indexes the address join returns across all symbols.
    frame_matches: usize,
    /// Source-position candidates gathered for one symbol.
    symbol_candidates: usize,
    /// Inline frames retained for one symbol.
    symbol_inline_frames: usize,
    /// Inline frames retained across all symbols.
    inline_frames: usize,
    /// Source-path bytes copied into retained inline frames.
    inline_source_bytes: usize,
}

impl DwarfBudget {
    /// The same bounds, none of them above the number of bytes the parse was
    /// given to read.
    ///
    /// Every structure a reader builds out of debug information takes at least
    /// one byte of that information to describe it, so a ceiling on the input
    /// is a ceiling on each of these counts as well. An operator who has said
    /// how many bytes an untrusted artifact may be read from has therefore
    /// already said how far the structures those bytes expand into may go, and
    /// this is that instruction reaching them — rather than a second set of
    /// numbers for the same decision that nobody set.
    ///
    /// Only ever narrows: an input ceiling above a default leaves the default
    /// standing, because these bounds are also what this build can afford.
    #[must_use]
    pub fn bounded_by(self, bytes: u64) -> Self {
        let bound = usize::try_from(bytes).unwrap_or(usize::MAX);
        Self {
            frames: self.frames.min(bound),
            line_records: self.line_records.min(bound),
            frame_matches: self.frame_matches.min(bound),
            symbol_candidates: self.symbol_candidates.min(bound),
            symbol_inline_frames: self.symbol_inline_frames.min(bound),
            inline_frames: self.inline_frames.min(bound),
            inline_source_bytes: self.inline_source_bytes.min(bound),
        }
    }
}

impl Default for DwarfBudget {
    fn default() -> Self {
        Self {
            frames: 250_000,
            line_records: 1_000_000,
            frame_matches: 1_000_000,
            symbol_candidates: 65_536,
            symbol_inline_frames: 4_096,
            inline_frames: 250_000,
            inline_source_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Attach optional DWARF locations to parser-established symbol identities.
///
/// Malformed or absent debug metadata deliberately degrades to no mappings.
/// Addresses are used only for the local join and are never stored as IDs.
pub fn attach_dwarf_frames<S: BuildHasher>(
    file: &object::File<'_>,
    symbol_addresses: &HashMap<ArtifactFingerprint, (u64, u64), S>,
    ir: &mut ArtifactIr,
    budget: DwarfBudget,
) {
    attach_dwarf_frames_within(file, symbol_addresses, ir, budget);
}

#[allow(
    clippy::too_many_lines,
    reason = "DWARF collection and the local address-to-symbol join form one parser boundary"
)]
fn attach_dwarf_frames_within<S: BuildHasher>(
    file: &object::File<'_>,
    symbol_addresses: &HashMap<ArtifactFingerprint, (u64, u64), S>,
    ir: &mut ArtifactIr,
    budget: DwarfBudget,
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
    'collect: loop {
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
        loop {
            let entry = match entries.next_dfs() {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(_) => {
                    ir.capabilities.debug_info_unreadable = true;
                    break;
                }
            };
            let depth = entry.depth();
            if !matches!(
                entry.tag(),
                gimli::DW_TAG_subprogram | gimli::DW_TAG_inlined_subroutine
            ) {
                continue;
            }
            let Some(frame) = source_frame(&dwarf, &unit, entry)
                .and_then(|frame| InternedFrame::intern(frame, &mut line_paths))
            else {
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
                    if frames.len() >= budget.frames {
                        ir.capabilities.debug_info_unreadable = true;
                        break 'collect;
                    }
                    frames.push(DwarfFrame {
                        begin: range.begin,
                        end: range.end,
                        depth,
                        frame,
                    });
                }
            }
        }
        let (records, truncated) = line_frames(
            &dwarf,
            &unit,
            &mut line_paths,
            budget.line_records.saturating_sub(line_records.len()),
        );
        line_records.extend(records);
        if truncated {
            ir.capabilities.debug_info_unreadable = true;
            break 'collect;
        }
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
    let frame_matches = frames_at_symbol_addresses(&frames, &symbols, budget.frame_matches);
    if frame_matches.truncated {
        ir.capabilities.debug_info_unreadable = true;
    }
    let symbol_rows: HashMap<_, _> = ir
        .symbols
        .iter()
        .enumerate()
        .map(|(index, symbol)| (symbol.fingerprint, index))
        .collect();
    let mut source_paths: BTreeSet<&str> = BTreeSet::new();
    let mut remaining_frames = budget.inline_frames;
    let mut remaining_source_bytes = budget.inline_source_bytes;
    for ((fingerprint, address, size), frame_indexes) in
        symbols.into_iter().zip(frame_matches.per_symbol)
    {
        if remaining_frames == 0 {
            ir.capabilities.debug_info_unreadable = true;
            break;
        }
        let mut truncated = frame_indexes.len() > budget.symbol_candidates;
        let mut matching: Vec<_> = frame_indexes
            .into_iter()
            .take(budget.symbol_candidates)
            .filter_map(|index| frames.get(index))
            .map(|frame| (frame.depth, frame.frame))
            .collect();
        let symbol_end = address.saturating_add(size);
        let line_start = line_records.partition_point(|candidate| candidate.address < address);
        for candidate in line_records
            .get(line_start..)
            .into_iter()
            .flatten()
            .take_while(|candidate| candidate.address < symbol_end)
        {
            if matching.len() >= budget.symbol_candidates {
                truncated = true;
                break;
            }
            matching.push((isize::MAX, candidate.interned_frame()));
        }
        // Candidates are ordered and deduplicated while their paths are still
        // interned, and only what survives the retention limits below is copied
        // out. Ordering reads the paths through the interner rather than
        // comparing their indexes, which record the order the paths were read
        // in and not the order they sort in.
        matching.sort_by(|left, right| {
            let path_of = |source| line_paths.get(source);
            (path_of(left.1.source), left.1.line, left.1.column, left.0).cmp(&(
                path_of(right.1.source),
                right.1.line,
                right.1.column,
                right.0,
            ))
        });
        matching.dedup_by(|left, right| left.1 == right.1);
        let retained = matching.len().min(budget.symbol_inline_frames).min(
            source_path_prefix_within(
                candidate_source_bytes(&matching, &line_paths),
                remaining_source_bytes,
            )
            .min(remaining_frames),
        );
        if retained < matching.len() {
            matching.truncate(retained);
            truncated = true;
        }
        remaining_frames -= matching.len();
        remaining_source_bytes = remaining_source_bytes
            .saturating_sub(candidate_source_bytes(&matching, &line_paths).sum());
        if truncated {
            ir.capabilities.debug_info_unreadable = true;
        }
        if matching.is_empty() {
            continue;
        }
        if let Some(index) = symbol_rows.get(&fingerprint) {
            source_paths.extend(
                matching
                    .iter()
                    .map(|(_, frame)| line_paths.get(frame.source)),
            );
            ir.symbols[*index].inline_stack = matching
                .into_iter()
                .map(|(_, frame)| frame.inline_frame(&line_paths))
                .collect();
        }
    }
    ir.source_mappings
        .extend(source_paths.into_iter().map(|uri| ArtifactSourceMapping {
            uri: uri.to_owned(),
        }));
}

const fn supports_address_join(kind: ObjectKind) -> bool {
    !matches!(kind, ObjectKind::Relocatable)
}

/// Source-path lengths of candidates, read without copying a path.
fn candidate_source_bytes<'a>(
    candidates: &'a [(isize, InternedFrame)],
    paths: &'a DwarfPathInterner,
) -> impl Iterator<Item = usize> + 'a {
    candidates
        .iter()
        .map(|(_, frame)| paths.get(frame.source).len())
}

/// Longest prefix of source paths whose bytes fit in a byte budget.
fn source_path_prefix_within(lengths: impl IntoIterator<Item = usize>, budget: usize) -> usize {
    let mut used = 0usize;
    let mut retained = 0usize;
    for length in lengths {
        used = used.saturating_add(length);
        if used > budget {
            break;
        }
        retained = retained.saturating_add(1);
    }
    retained
}

/// Frame indexes covering each symbol address, in symbol order.
#[derive(Debug, Default)]
struct FrameMatches {
    /// Indexes into the frame list, one entry per symbol.
    per_symbol: Vec<Vec<usize>>,
    /// Whether the index budget stopped the join short of every overlap.
    truncated: bool,
}

/// Join symbols to the frames covering their address.
///
/// The number of overlaps is the product of symbol count and nesting depth,
/// neither of which the accepted debug byte count bounds, so the total number
/// of returned indexes is capped and the shortfall is reported.
fn frames_at_symbol_addresses(
    frames: &[DwarfFrame],
    symbols: &[(ArtifactFingerprint, u64, u64)],
    budget: usize,
) -> FrameMatches {
    let mut active = BTreeSet::new();
    let mut next = 0;
    let mut remaining = budget;
    let mut truncated = false;
    let per_symbol = symbols
        .iter()
        .map(|(_, address, _)| {
            while next < frames.len() && frames[next].begin <= *address {
                active.insert((frames[next].end, next));
                next += 1;
            }
            while active.first().is_some_and(|(end, _)| *end <= *address) {
                let _ = active.pop_first();
            }
            let matched: Vec<_> = active
                .iter()
                .take(remaining)
                .map(|(_, index)| *index)
                .collect();
            truncated |= matched.len() < active.len();
            remaining -= matched.len();
            matched
        })
        .collect();
    FrameMatches {
        per_symbol,
        truncated,
    }
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

#[derive(Debug, Clone, Copy)]
struct DwarfFrame {
    begin: u64,
    end: u64,
    depth: isize,
    frame: InternedFrame,
}

/// A declaration position whose source path stays in the interner.
///
/// Retained frames greatly outnumber the distinct paths they name, so a frame
/// holds an index instead of its own copy of the path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InternedFrame {
    source: u32,
    line: Option<u32>,
    column: Option<u32>,
}

#[cfg(test)]
thread_local! {
    /// Source paths copied into an attached position on the current thread.
    ///
    /// Copying a path is the allocation the retention budgets bound, so a test
    /// counts the copies directly instead of timing the collection. Each test
    /// runs on its own thread, which keeps a count local to the collection it
    /// observes.
    static MATERIALIZED_SOURCE_PATHS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl InternedFrame {
    fn intern(frame: ArtifactInlineFrame, paths: &mut DwarfPathInterner) -> Option<Self> {
        Some(Self {
            source: paths.intern(frame.source)?,
            line: frame.line,
            column: frame.column,
        })
    }

    fn inline_frame(self, paths: &DwarfPathInterner) -> ArtifactInlineFrame {
        #[cfg(test)]
        MATERIALIZED_SOURCE_PATHS.with(|count| count.set(count.get() + 1));
        ArtifactInlineFrame {
            evidence_kind: crate::ArtifactSourceLocationEvidenceKind::Dwarf,
            source: paths.get(self.source).to_owned(),
            line: self.line,
            column: self.column,
        }
    }
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
    /// The position this row names, in the shape a declaration takes.
    const fn interned_frame(&self) -> InternedFrame {
        InternedFrame {
            source: self.source,
            line: Some(self.line),
            column: if self.column == 0 {
                None
            } else {
                Some(self.column)
            },
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

/// Collect a unit's line-table rows, up to `budget` of them.
///
/// One row costs a byte of debug information and a record here, so the row
/// count is bounded explicitly; the second return value reports whether rows
/// were left uncollected.
fn line_frames<R: Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    paths: &mut DwarfPathInterner,
    budget: usize,
) -> (Vec<DwarfLineFrame>, bool) {
    let Some(program) = unit.line_program.clone() else {
        return (Vec::new(), false);
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
        if frames.len() >= budget {
            return (frames, true);
        }
        frames.push(DwarfLineFrame {
            address: row.address(),
            source,
            line,
            column: column.unwrap_or(0),
        });
    }
    (frames, false)
}

/// File-table index of an attribute that names a declared source file.
///
/// A reader normalizes the file-naming attributes into a dedicated file-index
/// value that the generic unsigned-integer conversion does not accept, so
/// reading one only as an unsigned constant drops every declaration position
/// without reporting anything. Forms left as a plain constant are still read as
/// one, which keeps encodings the normalization does not reach.
fn file_index_value<R: Reader>(value: &gimli::AttributeValue<R>) -> Option<u64> {
    match value {
        gimli::AttributeValue::FileIndex(index) => Some(*index),
        other => other.udata_value(),
    }
}

fn source_frame<R: Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    entry: &gimli::DebuggingInformationEntry<R>,
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
        .and_then(|value| file_index_value(&value))?;
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
        .and_then(|value| value.udata_value())
        .and_then(|value| u32::try_from(value).ok());
    let column = entry
        .attr_value(attributes.2)
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    use super::{
        DwarfBudget, DwarfFrame, DwarfLineFrame, DwarfPathInterner, InternedFrame,
        attach_dwarf_frames_within, debug_section, file_index_value, frames_at_symbol_addresses,
        resolve_source_path, supports_address_join,
    };
    use crate::{
        ArtifactBackend, ArtifactFingerprint, ArtifactFormat, ArtifactInlineFrame, ArtifactIr,
    };
    use gimli::{AttributeValue, EndianSlice, RunTimeEndian};
    use object::ObjectKind;

    // What only the compiler-built object is read with. It is built where a C
    // compiler and a linker can be run from a test, so what reads it is bound
    // to the same platforms and so is what either of them names.
    #[cfg(unix)]
    use super::source_frame;
    #[cfg(unix)]
    use gimli::DwarfSections;
    #[cfg(unix)]
    use object::{Object, ObjectSection};

    const TEXT_FUNCTION: [u8; 8] = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3];
    const COMPILATION_DIRECTORY: &str = "/work";
    const UNIT_SOURCE: &str = "unit.c";

    /// Description of a synthetic executable carrying one DWARF 4 unit.
    ///
    /// Debug metadata describes address ranges and line-table rows in far fewer
    /// bytes than the structures a reader derives from them, which is what a
    /// hostile input exploits.
    #[derive(Debug)]
    struct DwarfFixture {
        /// Text symbols, each covering one eight-byte function.
        functions: usize,
        /// Subprogram entries, each with its own declaration line.
        subprograms: usize,
        /// Whether every entry's range spans the whole text section instead of
        /// one function.
        overlapping_ranges: bool,
        /// Line-table rows, each encoded as one special opcode.
        line_rows: usize,
        /// Whether each row advances the line as well as the address.
        distinct_row_lines: bool,
        /// A second declared file, named by every subprogram declaration while
        /// the rows keep naming the unit's own source. Declarations are read
        /// before rows, so this path is read first and, when it sorts after the
        /// unit source, the order paths are read in is not their sorted order.
        second_source: Option<&'static str>,
    }

    impl DwarfFixture {
        fn build(&self) -> Vec<u8> {
            use object::write::{Object as WriteObject, StandardSection, StandardSegment};
            use object::{
                Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind,
                SymbolScope,
                write::{Symbol, SymbolSection},
            };

            let mut object =
                WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
            let text = object.section_id(StandardSection::Text);
            for index in 0..self.functions {
                let offset = object.append_section_data(text, &TEXT_FUNCTION, 1);
                object.add_symbol(Symbol {
                    name: format!("function{index}").into_bytes(),
                    value: offset,
                    size: TEXT_FUNCTION.len() as u64,
                    kind: SymbolKind::Text,
                    scope: SymbolScope::Dynamic,
                    weak: false,
                    section: SymbolSection::Section(text),
                    flags: SymbolFlags::None,
                });
            }
            for (name, data) in [
                (".debug_abbrev", debug_abbrev()),
                (".debug_info", self.debug_info()),
                (
                    ".debug_line",
                    debug_line(self.line_rows, self.distinct_row_lines, self.second_source),
                ),
            ] {
                let section = object.add_section(
                    object.segment_name(StandardSegment::Debug).to_vec(),
                    name.as_bytes().to_vec(),
                    SectionKind::Debug,
                );
                object.append_section_data(section, &data, 1);
            }
            let mut bytes = object.write().expect("write DWARF fixture");
            // The object writer emits relocatable files only, and the address
            // join is defined for linked images, so the fixture declares
            // `ET_EXEC` in the ELF header's type field.
            bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
            bytes
        }

        fn debug_info(&self) -> Vec<u8> {
            let text_end = (self.functions * TEXT_FUNCTION.len()) as u64;
            let mut unit = Vec::new();
            unit.extend(4_u16.to_le_bytes());
            unit.extend(0_u32.to_le_bytes());
            unit.push(8);
            unit.push(1);
            unit.extend(UNIT_SOURCE.as_bytes());
            unit.push(0);
            unit.extend(COMPILATION_DIRECTORY.as_bytes());
            unit.push(0);
            unit.extend(0_u32.to_le_bytes());
            for index in 0..self.subprograms {
                let (low_pc, length) = if self.overlapping_ranges {
                    (0, text_end)
                } else {
                    let start = (index % self.functions.max(1)) * TEXT_FUNCTION.len();
                    (start as u64, TEXT_FUNCTION.len() as u64)
                };
                unit.push(2);
                unit.extend(format!("subprogram{index}").into_bytes());
                unit.push(0);
                unit.push(u8::from(self.second_source.is_some()) + 1);
                unit.extend(u16::try_from(index % 60_000).unwrap().to_le_bytes());
                unit.extend(low_pc.to_le_bytes());
                unit.extend(length.to_le_bytes());
            }
            unit.push(0);
            let mut section = u32::try_from(unit.len()).unwrap().to_le_bytes().to_vec();
            section.extend(unit);
            section
        }
    }

    /// The same unit in the shape a split-debug pair takes: one file keeps the
    /// code, another keeps the debug information, and a build ID ties them.
    ///
    /// A stripped image has no symbol table, so its code is one inferred region
    /// per text section — the case where a companion file is the only source
    /// evidence there is.
    struct SplitDebugFixture {
        /// Unit description both files of the pair agree on.
        unit: DwarfFixture,
        /// Container the file is written as.
        format: object::BinaryFormat,
        /// Whether the text symbols survive.
        text_symbols: bool,
        /// Whether the debug sections survive.
        debug_information: bool,
    }

    impl SplitDebugFixture {
        fn build(&self) -> Vec<u8> {
            use object::write::{Object as WriteObject, StandardSection, StandardSegment};
            use object::{
                Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind,
                SymbolScope,
                write::{Symbol, SymbolSection},
            };

            let mut object =
                WriteObject::new(self.format, Architecture::X86_64, Endianness::Little);
            let text = object.section_id(StandardSection::Text);
            for index in 0..self.unit.functions {
                let offset = object.append_section_data(text, &TEXT_FUNCTION, 1);
                if self.text_symbols {
                    object.add_symbol(Symbol {
                        name: format!("function{index}").into_bytes(),
                        value: offset,
                        size: TEXT_FUNCTION.len() as u64,
                        kind: SymbolKind::Text,
                        scope: SymbolScope::Dynamic,
                        weak: false,
                        section: SymbolSection::Section(text),
                        flags: SymbolFlags::None,
                    });
                }
            }
            if self.debug_information {
                for (name, data) in [
                    (".debug_abbrev", debug_abbrev()),
                    (".debug_info", self.unit.debug_info()),
                    (
                        ".debug_line",
                        debug_line(
                            self.unit.line_rows,
                            self.unit.distinct_row_lines,
                            self.unit.second_source,
                        ),
                    ),
                ] {
                    // Each container spells the same debug section its own way.
                    let name = if self.format == BinaryFormat::MachO {
                        format!("__{}", name.trim_start_matches('.'))
                    } else {
                        name.to_owned()
                    };
                    let section = object.add_section(
                        object.segment_name(StandardSegment::Debug).to_vec(),
                        name.into_bytes(),
                        SectionKind::Debug,
                    );
                    object.append_section_data(section, &data, 1);
                }
            }
            if self.format == BinaryFormat::Elf {
                let note = object.add_section(
                    Vec::new(),
                    b".note.gnu.build-id".to_vec(),
                    SectionKind::Note,
                );
                object.append_section_data(note, &build_id_note(), 4);
            }
            let mut bytes = object.write().expect("write split debug fixture");
            // The writer emits relocatable files only, and the address join is
            // defined for linked images, so each header declares one.
            if self.format == BinaryFormat::MachO {
                bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
            } else {
                bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
            }
            bytes
        }
    }

    /// The GNU build-ID note both files of a split-debug pair carry.
    fn build_id_note() -> Vec<u8> {
        let build_id = [7_u8; 20];
        let mut note = 4_u32.to_le_bytes().to_vec();
        note.extend(u32::try_from(build_id.len()).unwrap().to_le_bytes());
        note.extend(3_u32.to_le_bytes());
        note.extend(b"GNU\0");
        note.extend(build_id);
        note
    }

    /// One compilation unit and one subprogram declaration shape.
    fn debug_abbrev() -> Vec<u8> {
        vec![
            1, 0x11, 1, // compile unit, with children
            0x03, 0x08, // name, string
            0x1b, 0x08, // comp_dir, string
            0x10, 0x17, // stmt_list, sec_offset
            0, 0, //
            2, 0x2e, 0, // subprogram, without children
            0x03, 0x08, // name, string
            0x3a, 0x0b, // decl_file, data1
            0x3b, 0x05, // decl_line, data2
            0x11, 0x01, // low_pc, addr
            0x12, 0x07, // high_pc, data8
            0, 0, //
            0,
        ]
    }

    /// A DWARF 4 line program whose rows each occupy one special opcode.
    ///
    /// The opcode advances the address by one, so the rows land in the text
    /// section's first functions; it either repeats one line or advances the
    /// line with the address. The rows always name the first declared file,
    /// leaving a second declared file for the declarations to name.
    fn debug_line(rows: usize, distinct_lines: bool, second_source: Option<&str>) -> Vec<u8> {
        let mut header = vec![
            1,    // minimum instruction length
            1,    // maximum operations per instruction
            1,    // default is_stmt
            0xfb, // line base, -5
            14,   // line range
            13,   // opcode base
        ];
        header.extend([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
        header.push(0); // no include directories
        header.extend(UNIT_SOURCE.as_bytes());
        header.extend([0, 0, 0, 0]); // directory, modification time, length
        if let Some(source) = second_source {
            header.extend(source.as_bytes());
            header.extend([0, 0, 0, 0]); // directory, modification time, length
        }
        header.push(0); // no further file names

        let mut program = vec![0, 9, 0x02];
        program.extend(0_u64.to_le_bytes()); // set address
        let opcode = if distinct_lines { 0x21 } else { 0x20 };
        program.extend(std::iter::repeat_n(opcode, rows));
        program.extend([0, 1, 0x01]); // end sequence

        let mut unit = Vec::new();
        unit.extend(4_u16.to_le_bytes());
        unit.extend(u32::try_from(header.len()).unwrap().to_le_bytes());
        unit.extend(header);
        unit.extend(program);
        let mut section = u32::try_from(unit.len()).unwrap().to_le_bytes().to_vec();
        section.extend(unit);
        section
    }

    fn frame(begin: u64, end: u64) -> DwarfFrame {
        DwarfFrame {
            begin,
            end,
            depth: 0,
            frame: InternedFrame {
                source: 0,
                line: Some(1),
                column: None,
            },
        }
    }

    fn joined_symbols() -> [(ArtifactFingerprint, u64, u64); 3] {
        [
            (ArtifactFingerprint::from_content("test", b"first"), 12, 4),
            (ArtifactFingerprint::from_content("test", b"second"), 22, 2),
            (ArtifactFingerprint::from_content("test", b"third"), 45, 3),
        ]
    }

    /// Source positions of one symbol, in the order they were attached.
    fn inline_stack(ir: &ArtifactIr, name: &str) -> Vec<(String, Option<u32>, Option<u32>)> {
        ir.symbols
            .iter()
            .find(|symbol| symbol.name.as_deref() == Some(name))
            .map(|symbol| {
                symbol
                    .inline_stack
                    .iter()
                    .map(|frame| (frame.source.clone(), frame.line, frame.column))
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn frame_join_advances_a_sweep_index_without_rescanning_all_frames() {
        let frames = [frame(10, 30), frame(20, 25), frame(40, 50)];
        let matches = frames_at_symbol_addresses(&frames, &joined_symbols(), usize::MAX);

        assert_eq!(matches.per_symbol, vec![vec![0], vec![1, 0], vec![2]]);
        assert!(!matches.truncated);
    }

    #[test]
    fn the_frame_join_stops_at_its_index_budget_and_reports_the_shortfall() {
        let frames = [frame(10, 30), frame(20, 25), frame(40, 50)];
        let matches = frames_at_symbol_addresses(&frames, &joined_symbols(), 2);

        assert_eq!(matches.per_symbol, vec![vec![0], vec![1], Vec::new()]);
        assert!(matches.truncated);
    }

    #[test]
    fn a_well_formed_unit_maps_every_symbol_to_its_declared_and_line_table_positions() {
        let ir = crate::elf::ElfBackend
            .parse_with_debug_companion(
                &DwarfFixture {
                    functions: 3,
                    subprograms: 3,
                    overlapping_ranges: false,
                    line_rows: 12,
                    distinct_row_lines: false,
                    second_source: None,
                }
                .build(),
                None,
            )
            .unwrap();

        // Each symbol carries the declaration position of the subprogram
        // covering it and the positions of the line-table rows inside it. The
        // second symbol's two sources agree on one position and are kept once;
        // the third is covered by a declaration alone, no row reaching it.
        assert_eq!(
            inline_stack(&ir, "function0"),
            vec![
                ("/work/unit.c".to_owned(), Some(0), None),
                ("/work/unit.c".to_owned(), Some(1), None),
            ]
        );
        assert_eq!(
            inline_stack(&ir, "function1"),
            vec![("/work/unit.c".to_owned(), Some(1), None)]
        );
        assert_eq!(
            inline_stack(&ir, "function2"),
            vec![("/work/unit.c".to_owned(), Some(2), None)]
        );
        assert_eq!(
            ir.source_mappings
                .iter()
                .map(|mapping| mapping.uri.clone())
                .collect::<Vec<_>>(),
            vec!["/work/unit.c".to_owned()]
        );
        assert!(!ir.capabilities.debug_info_unreadable);
    }

    /// Attach a fixture's debug information under an explicit budget.
    fn attach_within(fixture: &DwarfFixture, budget: DwarfBudget) -> ArtifactIr {
        let bytes = fixture.build();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut ir = ArtifactIr::empty(ArtifactFormat::Elf, &bytes);
        let addresses: HashMap<_, _> = crate::native::collect_text_symbols(&file, &mut ir)
            .unwrap()
            .into_iter()
            .map(|range| (range.fingerprint, (range.address, range.size)))
            .collect();
        attach_dwarf_frames_within(&file, &addresses, &mut ir, budget);
        ir
    }

    fn attached_frames(ir: &ArtifactIr) -> usize {
        ir.symbols
            .iter()
            .map(|symbol| symbol.inline_stack.len())
            .sum()
    }

    #[test]
    fn a_line_table_larger_than_its_budget_keeps_the_rows_it_read() {
        let fixture = DwarfFixture {
            functions: 3,
            subprograms: 0,
            overlapping_ranges: false,
            line_rows: 12,
            distinct_row_lines: true,
            second_source: None,
        };

        let full = attach_within(&fixture, DwarfBudget::default());
        let capped = attach_within(
            &fixture,
            DwarfBudget {
                line_records: 4,
                ..DwarfBudget::default()
            },
        );

        assert!(!full.capabilities.debug_info_unreadable);
        assert_eq!(attached_frames(&full), 12);
        assert!(capped.capabilities.debug_info_unreadable);
        assert_eq!(attached_frames(&capped), 4);
        assert_eq!(
            inline_stack(&capped, "function0"),
            (2..=5)
                .map(|line| ("/work/unit.c".to_owned(), Some(line), None))
                .collect::<Vec<_>>()
        );
    }

    /// An input ceiling reaches the structures the input expands into.
    ///
    /// Debug metadata describes far more than it occupies, so a parse held to
    /// N bytes can still build far more than N frames unless something says
    /// otherwise. This is that something, and it is the only knob an operator
    /// has to turn: the numbers here are the ones they already set.
    #[test]
    fn an_input_ceiling_bounds_what_the_debug_information_expands_into() {
        let fixture = DwarfFixture {
            functions: 2,
            subprograms: 0,
            overlapping_ranges: false,
            line_rows: 12,
            distinct_row_lines: true,
            second_source: None,
        };

        let full = attach_within(&fixture, DwarfBudget::default());
        let bounded = attach_within(&fixture, DwarfBudget::default().bounded_by(4));

        assert!(!full.capabilities.debug_info_unreadable);
        assert_eq!(attached_frames(&full), 12);
        assert!(bounded.capabilities.debug_info_unreadable);
        assert!(attached_frames(&bounded) < attached_frames(&full));

        // Only ever narrows: a ceiling above what this build can afford leaves
        // this build's own bounds standing.
        let generous = DwarfBudget::default().bounded_by(u64::MAX);
        assert_eq!(generous.frames, DwarfBudget::default().frames);
        assert_eq!(
            generous.inline_source_bytes,
            DwarfBudget::default().inline_source_bytes
        );
    }

    #[test]
    fn one_symbol_retains_no_more_inline_frames_than_its_budget() {
        let fixture = DwarfFixture {
            functions: 2,
            subprograms: 0,
            overlapping_ranges: false,
            line_rows: 12,
            distinct_row_lines: true,
            second_source: None,
        };

        let ir = attach_within(
            &fixture,
            DwarfBudget {
                symbol_inline_frames: 3,
                ..DwarfBudget::default()
            },
        );

        assert!(ir.capabilities.debug_info_unreadable);
        assert!(
            ir.symbols
                .iter()
                .all(|symbol| symbol.inline_stack.len() <= 3)
        );
        assert_eq!(
            inline_stack(&ir, "function0"),
            (2..=4)
                .map(|line| ("/work/unit.c".to_owned(), Some(line), None))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn source_candidates_of_one_symbol_stop_at_their_budget() {
        let fixture = DwarfFixture {
            functions: 2,
            subprograms: 0,
            overlapping_ranges: false,
            line_rows: 12,
            distinct_row_lines: true,
            second_source: None,
        };

        let ir = attach_within(
            &fixture,
            DwarfBudget {
                symbol_candidates: 2,
                ..DwarfBudget::default()
            },
        );

        assert!(ir.capabilities.debug_info_unreadable);
        assert_eq!(
            inline_stack(&ir, "function0"),
            (2..=3)
                .map(|line| ("/work/unit.c".to_owned(), Some(line), None))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn inline_frames_across_symbols_stop_at_their_shared_budgets() {
        let fixture = DwarfFixture {
            functions: 3,
            subprograms: 0,
            overlapping_ranges: false,
            line_rows: 20,
            distinct_row_lines: true,
            second_source: None,
        };

        let by_count = attach_within(
            &fixture,
            DwarfBudget {
                inline_frames: 5,
                ..DwarfBudget::default()
            },
        );
        let by_source_bytes = attach_within(
            &fixture,
            DwarfBudget {
                inline_source_bytes: 3 * "/work/unit.c".len(),
                ..DwarfBudget::default()
            },
        );

        assert!(by_count.capabilities.debug_info_unreadable);
        assert_eq!(attached_frames(&by_count), 5);
        assert!(by_source_bytes.capabilities.debug_info_unreadable);
        assert_eq!(attached_frames(&by_source_bytes), 3);
    }

    #[test]
    fn debug_information_that_expands_far_past_its_own_size_stays_within_its_budgets() {
        let budget = DwarfBudget::default();
        let bytes = DwarfFixture {
            functions: 64,
            subprograms: 100_000,
            overlapping_ranges: true,
            line_rows: 3_000_000,
            distinct_row_lines: true,
            second_source: None,
        }
        .build();

        let started = Instant::now();
        let ir = crate::elf::ElfBackend
            .parse_with_debug_companion(&bytes, None)
            .unwrap();
        let elapsed = started.elapsed();

        assert!(ir.capabilities.debug_info_unreadable);
        assert!(
            ir.symbols
                .iter()
                .all(|symbol| symbol.inline_stack.len() <= budget.symbol_inline_frames)
        );
        assert!(attached_frames(&ir) <= budget.inline_frames);
        assert!(
            ir.source_mappings
                .iter()
                .map(|mapping| mapping.uri.len())
                .sum::<usize>()
                <= budget.inline_source_bytes
        );
        assert!(elapsed < Duration::from_secs(30), "parse took {elapsed:?}");
    }

    #[test]
    fn every_structure_derived_from_debug_information_has_a_bounded_footprint() {
        let budget = DwarfBudget::default();
        let retained = budget.frames * size_of::<DwarfFrame>()
            + budget.line_records * size_of::<DwarfLineFrame>()
            + budget.frame_matches * size_of::<usize>()
            + budget.symbol_candidates * size_of::<(isize, InternedFrame)>()
            + budget.inline_frames * size_of::<ArtifactInlineFrame>()
            + budget.inline_source_bytes;

        assert!(size_of::<DwarfFrame>() <= 48);
        // A candidate carries no path of its own, so the candidate list of one
        // symbol costs less than the positions it is narrowed down to.
        assert!(size_of::<(isize, InternedFrame)>() < size_of::<ArtifactInlineFrame>());
        assert!(
            retained <= 256 * 1024 * 1024,
            "derived structures reserve {retained} bytes"
        );
    }

    /// Unit shapes whose attached positions are pinned by an exact expectation.
    ///
    /// Between them the shapes cover a declaration per function, declarations
    /// that all cover the same text, rows that repeat one position, and rows
    /// that walk the lines of a function they share with a declaration.
    fn pinned_unit_shapes() -> Vec<DwarfFixture> {
        vec![
            DwarfFixture {
                functions: 3,
                subprograms: 3,
                overlapping_ranges: false,
                line_rows: 12,
                distinct_row_lines: false,
                second_source: None,
            },
            DwarfFixture {
                functions: 3,
                subprograms: 3,
                overlapping_ranges: false,
                line_rows: 12,
                distinct_row_lines: true,
                second_source: None,
            },
            DwarfFixture {
                functions: 3,
                subprograms: 5,
                overlapping_ranges: true,
                line_rows: 9,
                distinct_row_lines: true,
                second_source: None,
            },
        ]
    }

    /// One attached source position: its path, line, and column.
    type Position = (String, Option<u32>, Option<u32>);

    /// Positions naming consecutive lines of one source path.
    fn positions(path: &str, lines: impl IntoIterator<Item = u32>) -> Vec<Position> {
        lines
            .into_iter()
            .map(|line| (path.to_owned(), Some(line), None))
            .collect()
    }

    /// Source positions of every code record, in the order they were attached.
    fn inline_stacks(ir: &ArtifactIr) -> Vec<Vec<Position>> {
        ir.symbols
            .iter()
            .map(|symbol| {
                symbol
                    .inline_stack
                    .iter()
                    .map(|frame| (frame.source.clone(), frame.line, frame.column))
                    .collect()
            })
            .collect()
    }

    fn source_uris(ir: &ArtifactIr) -> Vec<String> {
        ir.source_mappings
            .iter()
            .map(|mapping| mapping.uri.clone())
            .collect()
    }

    #[test]
    fn every_unit_shape_maps_its_symbols_to_a_fixed_set_of_positions() {
        const UNIT: &str = "/work/unit.c";
        let expected = vec![
            vec![
                positions(UNIT, [0, 1]),
                positions(UNIT, [1]),
                positions(UNIT, [2]),
            ],
            vec![
                [positions(UNIT, [0]), positions(UNIT, 2..=8)].concat(),
                [positions(UNIT, [1]), positions(UNIT, 9..=13)].concat(),
                positions(UNIT, [2]),
            ],
            vec![
                positions(UNIT, 0..=8),
                [positions(UNIT, 0..=4), positions(UNIT, 9..=10)].concat(),
                positions(UNIT, 0..=4),
            ],
        ];

        for (fixture, expected) in pinned_unit_shapes().into_iter().zip(expected) {
            let ir = attach_within(&fixture, DwarfBudget::default());

            assert_eq!(inline_stacks(&ir), expected, "{fixture:?}");
            assert_eq!(source_uris(&ir), vec![UNIT.to_owned()], "{fixture:?}");
            assert!(!ir.capabilities.debug_info_unreadable, "{fixture:?}");
        }
    }

    #[test]
    fn positions_of_one_symbol_are_ordered_by_source_path_not_by_when_it_was_read() {
        // Declarations are read before line-table rows, so this unit's
        // declared file is read first while sorting after the file its rows
        // name. Attached positions follow the paths, not the reading order.
        let ir = attach_within(
            &DwarfFixture {
                functions: 2,
                subprograms: 2,
                overlapping_ranges: true,
                line_rows: 6,
                distinct_row_lines: true,
                second_source: Some("/zzz.c"),
            },
            DwarfBudget::default(),
        );

        assert_eq!(
            inline_stack(&ir, "function0"),
            [positions("/work/unit.c", 2..=7), positions("/zzz.c", 0..=1)].concat()
        );
        assert_eq!(
            source_uris(&ir),
            vec!["/work/unit.c".to_owned(), "/zzz.c".to_owned()]
        );
        assert!(!ir.capabilities.debug_info_unreadable);
    }

    /// Run a collection, reporting the source paths it copied out of the
    /// interner alongside its result.
    fn source_paths_copied<T>(collect: impl FnOnce() -> T) -> (T, usize) {
        super::MATERIALIZED_SOURCE_PATHS.with(|copied| copied.set(0));
        let value = collect();
        (
            value,
            super::MATERIALIZED_SOURCE_PATHS.with(std::cell::Cell::get),
        )
    }

    #[test]
    fn source_paths_are_copied_only_for_the_positions_a_symbol_retains() {
        let budget = DwarfBudget::default();
        let bytes = DwarfFixture {
            functions: 64,
            subprograms: 100_000,
            overlapping_ranges: true,
            line_rows: 200_000,
            distinct_row_lines: true,
            second_source: None,
        }
        .build();

        let (ir, copied) = source_paths_copied(|| {
            crate::elf::ElfBackend
                .parse_with_debug_companion(&bytes, None)
                .unwrap()
        });

        // Candidates outnumber retained positions here by more than an order of
        // magnitude, so a copy per candidate would leave the budget behind.
        assert_eq!(copied, attached_frames(&ir), "{copied} paths copied");
        assert!(copied <= budget.inline_frames, "{copied} paths copied");
    }

    #[test]
    fn a_stripped_image_and_its_debug_companion_map_what_the_same_code_maps_elsewhere() {
        let unit = || DwarfFixture {
            functions: 3,
            subprograms: 3,
            overlapping_ranges: false,
            line_rows: 12,
            distinct_row_lines: false,
            second_source: None,
        };
        let split = |text_symbols, debug_information, format| {
            SplitDebugFixture {
                unit: unit(),
                format,
                text_symbols,
                debug_information,
            }
            .build()
        };

        let stripped = crate::elf::ElfBackend
            .parse_with_debug_companion(
                &split(false, false, object::BinaryFormat::Elf),
                Some(&split(false, true, object::BinaryFormat::Elf)),
            )
            .unwrap();
        let elsewhere = crate::macho::MachOBackend
            .parse(&split(false, true, object::BinaryFormat::MachO))
            .unwrap();

        assert_eq!(source_uris(&stripped), vec!["/work/unit.c".to_owned()]);
        assert_eq!(source_uris(&stripped), source_uris(&elsewhere));
        assert_eq!(inline_stacks(&stripped), inline_stacks(&elsewhere));
        assert!(stripped.capabilities.source_mapping);
        assert!(!stripped.capabilities.debug_info_unreadable);
        assert!(
            stripped.symbols.iter().all(|symbol| symbol.size_inferred),
            "the stripped image has no symbol table to name its code"
        );
    }

    #[test]
    fn a_file_naming_attribute_yields_an_index_a_plain_unsigned_read_does_not() {
        let normalized: AttributeValue<EndianSlice<'_, RunTimeEndian>> =
            AttributeValue::FileIndex(3);
        let constant: AttributeValue<EndianSlice<'_, RunTimeEndian>> = AttributeValue::Data1(3);

        assert_eq!(normalized.udata_value(), None);
        assert_eq!(file_index_value(&normalized), Some(3));
        assert_eq!(file_index_value(&constant), Some(3));
    }

    /// Declaration positions of every subprogram an object's debug information
    /// describes, read the way the address join reads them.
    ///
    /// Confined to the platforms that can build the object it reads, like the
    /// compiler run that produces one: elsewhere it has no caller, and a
    /// helper without one fails the build.
    #[cfg(unix)]
    fn declaration_frames(file: &object::File<'_>) -> Vec<ArtifactInlineFrame> {
        let endian = match file.endianness() {
            object::Endianness::Little => RunTimeEndian::Little,
            object::Endianness::Big => RunTimeEndian::Big,
        };
        let sections = DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                debug_section(file, id.name())
                    .and_then(|section| section.uncompressed_data().ok())
                    .map(std::borrow::Cow::into_owned)
                    .unwrap_or_default(),
            )
        })
        .expect("load debug sections");
        let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
        let mut frames = Vec::new();
        let mut units = dwarf.units();
        while let Some(header) = units.next().expect("read unit header") {
            let unit = dwarf.unit(header).expect("read unit");
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs().expect("read entry") {
                if entry.tag() == gimli::DW_TAG_subprogram
                    && let Some(frame) = source_frame(&dwarf, &unit, entry)
                {
                    frames.push(frame);
                }
            }
        }
        frames
    }

    /// Compile one translation unit with the host C compiler, keeping its debug
    /// information. Only the compiler runs; the image is never loaded.
    ///
    /// The declared source names two functions on known lines, so a frame from
    /// a subprogram's declaration is recognisable by its line alone.
    ///
    /// Whether the unit is linked is not a stylistic choice; it is where each
    /// object format holds readable debug information. In an unlinked ELF
    /// object the line program stores its file and directory names as zero and
    /// carries the real offsets in relocations against `.debug_line_str`, so
    /// the names only resolve once a linker has applied them. A Mach-O link
    /// goes the other way and moves debug information out of the image into a
    /// debug map, leaving the DWARF behind in the unlinked object.
    #[cfg(unix)]
    #[allow(
        clippy::disallowed_types,
        reason = "the fixture is built by a compiler run from the test, never from a scan"
    )]
    fn compiler_generated_object() -> Option<Vec<u8>> {
        use std::process::Command;

        let compiler = std::env::var("CC").unwrap_or_else(|_| "cc".to_owned());
        let directory = std::env::temp_dir().join(format!(
            "codehelion-dwarf-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let linked = !cfg!(target_vendor = "apple");
        std::fs::create_dir_all(&directory).expect("create the compilation directory");
        let source = directory.join("unit.c");
        let object = directory.join(if linked { "unit.so" } else { "unit.o" });
        std::fs::write(
            &source,
            "int declared_first(void) { return 1; }\nint declared_second(int value) { return value + 1; }\n",
        )
        .expect("write the translation unit");
        let mut command = Command::new(compiler);
        command.arg("-g").arg("-O0");
        if linked {
            command.arg("-shared").arg("-fPIC");
        } else {
            command.arg("-c");
        }
        let status = command.arg(&source).arg("-o").arg(&object).status();
        let bytes = match status {
            Ok(status) if status.success() => {
                Some(std::fs::read(&object).expect("read the object"))
            }
            _ => None,
        };
        let _ = std::fs::remove_dir_all(&directory);
        bytes
    }

    #[cfg(unix)]
    #[test]
    fn declaration_positions_of_compiler_generated_debug_information_become_frames() {
        let bytes =
            compiler_generated_object().expect("a C compiler emitting debug information is needed");
        let file = object::File::parse(bytes.as_slice()).expect("parse the compiled object");
        let frames = declaration_frames(&file);

        assert!(
            frames
                .iter()
                .any(|frame| frame.source.ends_with("unit.c") && frame.line == Some(1)),
            "no frame for the first declaration: {frames:?}"
        );
        assert!(
            frames
                .iter()
                .any(|frame| frame.source.ends_with("unit.c") && frame.line == Some(2)),
            "no frame for the second declaration: {frames:?}"
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
        assert_eq!(
            frame.interned_frame().inline_frame(&paths).source,
            "/work/src/lib.rs"
        );
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
