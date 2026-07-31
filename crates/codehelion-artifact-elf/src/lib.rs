//! ELF implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the artifact.

use codehelion_artifact::{
    ArtifactBackend, ArtifactCall, ArtifactCapabilities, ArtifactDataSegment, ArtifactError,
    ArtifactFingerprint, ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactInlineFrame,
    ArtifactIr, ArtifactRelocation, ArtifactSection, ArtifactSourceMapping, ArtifactSymbol,
    NormalizedInstructions, UnresolvedCall,
};
use gimli::{DwarfSections, EndianSlice, Reader, RunTimeEndian};
use iced_x86::{Decoder, DecoderOptions, OpKind};
use object::{
    Architecture, Endianness, Object, ObjectSection, ObjectSymbol, RelocationKind,
    RelocationTarget, SectionKind, SymbolKind,
};
use std::collections::{BTreeSet, HashMap, HashSet};

/// Parser backend for ELF artifacts.
#[derive(Debug, Default, Clone, Copy)]
pub struct ElfBackend;

/// Version of the x86 instruction-shape normalization representation.
pub const ELF_NORMALIZATION_VERSION: &str = "x86-operand-shape-v1";

impl ArtifactBackend for ElfBackend {
    fn format(&self) -> ArtifactFormat {
        ArtifactFormat::Elf
    }

    fn detects(&self, bytes: &[u8]) -> bool {
        bytes.starts_with(b"\x7fELF")
    }

    fn parse(&self, bytes: &[u8]) -> Result<ArtifactIr, ArtifactError> {
        self.parse_with_debug_companion(bytes, None)
    }

    fn capabilities(&self) -> ArtifactCapabilities {
        ArtifactCapabilities {
            symbols: true,
            call_graph: true,
            source_mapping: false,
            relocations: false,
            data_segments: true,
        }
    }
}

impl ElfBackend {
    /// Parse an ELF artifact with an optional, already-read external debug ELF.
    ///
    /// The companion is accepted only when both files declare the same GNU build
    /// ID. This prevents a path supplied for one build from attributing source
    /// locations to a different artifact. No companion means the normal
    /// debug-information-absent fallback; neither path opens files or executes
    /// inspected code.
    ///
    /// # Errors
    ///
    /// Returns an error when either input is not an ELF file, or when a supplied
    /// companion does not carry the same build ID as the inspected artifact.
    #[allow(
        clippy::too_many_lines,
        reason = "parsing one artifact keeps all fallible format reads in one transaction"
    )]
    pub fn parse_with_debug_companion(
        &self,
        bytes: &[u8],
        debug_companion: Option<&[u8]>,
    ) -> Result<ArtifactIr, ArtifactError> {
        if !self.detects(bytes) {
            return Err(ArtifactError::WrongFormat {
                expected: ArtifactFormat::Elf,
            });
        }
        let file = object::File::parse(bytes).map_err(|error| malformed(error.to_string()))?;
        let debug_file = debug_companion
            .map(|companion| {
                let companion =
                    object::File::parse(companion).map_err(|error| malformed(error.to_string()))?;
                if !matching_build_id(&file, &companion) {
                    return Err(malformed(
                        "external debug companion does not have the artifact's build ID".to_owned(),
                    ));
                }
                Ok(companion)
            })
            .transpose()?;
        let mut ir = ArtifactIr::empty(ArtifactFormat::Elf, bytes);
        let mut symbol_fingerprints = HashMap::new();
        let mut symbol_addresses = HashMap::new();
        let mut symbol_addresses_by_fingerprint = HashMap::new();
        collect_sections(&file, &mut ir)?;
        collect_dynamic_function_imports(&file, &mut ir);
        for symbol in file.symbols() {
            if symbol.kind() != SymbolKind::Text || symbol.size() == 0 {
                continue;
            }
            let Some(section_index) = symbol.section_index() else {
                continue;
            };
            let section = file
                .section_by_index(section_index)
                .map_err(|error| malformed(error.to_string()))?;
            let Some(relative) = symbol.address().checked_sub(section.address()) else {
                continue;
            };
            let data = section
                .data()
                .map_err(|error| malformed(error.to_string()))?;
            let Ok(start) = usize::try_from(relative) else {
                continue;
            };
            let Ok(size) = usize::try_from(symbol.size()) else {
                continue;
            };
            let Some(code) = data.get(start..start.saturating_add(size)) else {
                continue;
            };
            let (section_offset, _) = section.file_range().unwrap_or((0, 0));
            let name = symbol
                .name()
                .ok()
                .filter(|name| !name.is_empty())
                .map(demangle);
            let normalized = normalize_x86(code, file.architecture());
            ir.symbols.push(ArtifactSymbol {
                fingerprint: symbol_fingerprint(
                    name.as_deref(),
                    section.name().ok(),
                    normalized.as_ref(),
                    code,
                ),
                name,
                exported: symbol.is_global(),
                section: u32::try_from(section_index.0).ok(),
                offset: section_offset.saturating_add(relative),
                size: symbol.size(),
                size_inferred: false,
                code: code.to_vec(),
                normalized,
                inline_stack: Vec::new(),
            });
            if let Some(fingerprint) = ir.symbols.last().map(|value| value.fingerprint) {
                symbol_fingerprints.insert(symbol.index(), Some(fingerprint));
                symbol_addresses
                    .entry(symbol.address())
                    .or_insert(fingerprint);
                symbol_addresses_by_fingerprint
                    .insert(fingerprint, (symbol.address(), symbol.size()));
            }
        }
        if ir.symbols.is_empty() {
            infer_text_regions(&file, &mut ir)?;
        }
        record_entry_point(file.entry(), &symbol_addresses, &mut ir);
        record_init_fini_roots(&file, &symbol_fingerprints, &symbol_addresses, &mut ir);
        let symbols = ir.symbols.clone();
        record_x86_direct_calls(
            &file,
            &symbols,
            &symbol_fingerprints,
            &symbol_addresses,
            &mut ir,
        )?;
        collect_dwarf_frames(
            debug_file.as_ref().unwrap_or(&file),
            &symbol_addresses_by_fingerprint,
            &mut ir,
        );
        ir.capabilities = ArtifactCapabilities {
            symbols: !ir.symbols.is_empty(),
            call_graph: !ir.calls.is_empty(),
            source_mapping: !ir.source_mappings.is_empty(),
            relocations: !ir.relocations.is_empty(),
            data_segments: !ir.data_segments.is_empty(),
        };
        Ok(ir)
    }
}

/// Whether a separately supplied debug ELF can safely describe `artifact`.
///
/// An absent build ID is insufficient evidence: loading its line table would
/// make an unrelated file look like a direct source-location correspondence.
fn matching_build_id(artifact: &object::File<'_>, companion: &object::File<'_>) -> bool {
    let Ok(Some(artifact_id)) = artifact.build_id() else {
        return false;
    };
    let Ok(Some(companion_id)) = companion.build_id() else {
        return false;
    };
    artifact_id == companion_id
}

/// Record dynamic function references without attempting to load their library.
fn collect_dynamic_function_imports(file: &object::File<'_>, ir: &mut ArtifactIr) {
    let mut names = BTreeSet::new();
    for symbol in file.dynamic_symbols() {
        if symbol.kind() == SymbolKind::Text && symbol.is_undefined() {
            if let Some(name) = symbol
                .name()
                .ok()
                .filter(|name| !name.is_empty())
                .map(demangle)
            {
                names.insert(name);
            }
        }
    }
    ir.imports
        .extend(names.into_iter().map(|name| ArtifactImport {
            module: None,
            name: Some(name),
            kind: ArtifactImportKind::Function,
        }));
}

/// Preserve an ELF entry address only after resolving it to a stable symbol ID.
///
/// A zero entry address is the conventional absence marker for relocatable
/// objects. Addresses are lookup evidence only and never become part of IR
/// identity.
fn record_entry_point(
    entry_address: u64,
    addresses: &HashMap<u64, ArtifactFingerprint>,
    ir: &mut ArtifactIr,
) {
    if entry_address != 0 {
        if let Some(fingerprint) = addresses.get(&entry_address) {
            ir.entry_points.push(*fingerprint);
        }
    }
}

/// Treat constructor and destructor arrays as conservative local roots.
///
/// A relocation in either array is loader evidence that the target can run
/// even without a normal call edge or external export. The section and symbol
/// indexes are used only while parsing; the IR records the stable fingerprint.
fn record_init_fini_roots(
    file: &object::File<'_>,
    fingerprints: &HashMap<object::SymbolIndex, Option<ArtifactFingerprint>>,
    addresses: &HashMap<u64, ArtifactFingerprint>,
    ir: &mut ArtifactIr,
) {
    let mut roots = BTreeSet::new();
    for section in file.sections() {
        if !matches!(section.name().ok(), Some(".init_array" | ".fini_array")) {
            continue;
        }
        for (_, relocation) in section.relocations() {
            if let RelocationTarget::Symbol(index) = relocation.target() {
                if let Some(Some(fingerprint)) = fingerprints.get(&index) {
                    roots.insert(*fingerprint);
                }
            }
        }
        if let Ok(data) = section.data() {
            roots.extend(pointer_roots(
                data,
                file.is_64(),
                file.endianness(),
                addresses,
            ));
        }
    }
    let existing: BTreeSet<_> = ir.entry_points.iter().copied().collect();
    ir.entry_points.extend(
        roots
            .into_iter()
            .filter(|fingerprint| !existing.contains(fingerprint)),
    );
}

/// Resolve pointer-width values retained in a linked init/fini array.
fn pointer_roots(
    bytes: &[u8],
    is_64: bool,
    endianness: Endianness,
    addresses: &HashMap<u64, ArtifactFingerprint>,
) -> BTreeSet<ArtifactFingerprint> {
    let width = if is_64 { 8 } else { 4 };
    bytes
        .chunks_exact(width)
        .filter_map(|chunk| pointer_value(chunk, endianness))
        .filter_map(|address| addresses.get(&address).copied())
        .collect()
}

fn pointer_value(bytes: &[u8], endianness: Endianness) -> Option<u64> {
    match bytes.len() {
        4 => {
            let bytes: [u8; 4] = bytes.try_into().ok()?;
            Some(match endianness {
                Endianness::Little => u64::from(u32::from_le_bytes(bytes)),
                Endianness::Big => u64::from(u32::from_be_bytes(bytes)),
            })
        }
        8 => {
            let bytes: [u8; 8] = bytes.try_into().ok()?;
            Some(match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            })
        }
        _ => None,
    }
}

/// Attach local DWARF source locations to known symbol identities.
///
/// Debug metadata is optional evidence. A malformed or unavailable DWARF
/// section therefore degrades to no mappings; it never changes whether the
/// ELF itself can be analysed. Addresses are used only while joining parser
/// observations to the already content-addressed symbols.
fn collect_dwarf_frames(
    file: &object::File<'_>,
    symbol_addresses: &HashMap<ArtifactFingerprint, (u64, u64)>,
    ir: &mut ArtifactIr,
) {
    let endian = match file.endianness() {
        Endianness::Little => RunTimeEndian::Little,
        Endianness::Big => RunTimeEndian::Big,
    };
    let Ok(sections) = DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            file.section_by_name(id.name())
                .and_then(|section| section.data().ok())
                .unwrap_or_default()
                .to_vec(),
        )
    }) else {
        return;
    };
    let dwarf = sections.borrow(|section| EndianSlice::new(section, endian));
    let mut frames = Vec::new();
    let mut line_frames = Vec::new();
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
            let Some(frame) = dwarf_source_frame(&dwarf, &unit, entry) else {
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
        line_frames.extend(dwarf_line_frames(&dwarf, &unit));
    }
    if frames.is_empty() && line_frames.is_empty() {
        return;
    }
    let mut source_paths = BTreeSet::new();
    for (fingerprint, (address, size)) in symbol_addresses {
        let mut matching: Vec<_> = frames
            .iter()
            .filter(|candidate| candidate.begin <= *address && *address < candidate.end)
            .map(|candidate| (candidate.depth, candidate.frame.clone()))
            .collect::<Vec<_>>();
        let symbol_end = address.saturating_add(*size);
        matching.extend(
            line_frames
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

/// Collect source rows that occur inside symbol ranges.
///
/// The DWARF subprogram record is anchored at a declaration, which can sit
/// outside a clone fragment. Line rows retain the locations of instructions
/// inside that symbol without making the line-table address part of identity.
fn dwarf_line_frames<R: Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
) -> Vec<DwarfLineFrame> {
    let Some(program) = unit.line_program.clone() else {
        return Vec::new();
    };
    let compilation_directory = unit.comp_dir.as_ref().and_then(|value| {
        value
            .to_string_lossy()
            .ok()
            .map(std::borrow::Cow::into_owned)
    });
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
            .and_then(|value| {
                value
                    .to_string_lossy()
                    .ok()
                    .map(std::borrow::Cow::into_owned)
            })
        else {
            continue;
        };
        let directory = file
            .directory(header)
            .and_then(|value| dwarf.attr_string(unit, value).ok())
            .and_then(|value| {
                value
                    .to_string_lossy()
                    .ok()
                    .map(std::borrow::Cow::into_owned)
            });
        let column = match row.column() {
            gimli::ColumnType::LeftEdge => None,
            gimli::ColumnType::Column(value) => u32::try_from(value.get()).ok(),
        };
        frames.push(DwarfLineFrame {
            address: row.address(),
            frame: ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: resolve_dwarf_source_path(
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

fn dwarf_source_frame<R: Reader>(
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
        .ok()?
        .to_string_lossy()
        .ok()?
        .into_owned();
    let directory = file
        .directory(line_program.header())
        .and_then(|value| dwarf.attr_string(unit, value).ok())
        .and_then(|value| {
            value
                .to_string_lossy()
                .ok()
                .map(std::borrow::Cow::into_owned)
        });
    let compilation_directory = unit.comp_dir.as_ref().and_then(|value| {
        value
            .to_string_lossy()
            .ok()
            .map(std::borrow::Cow::into_owned)
    });
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
        evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
        source: resolve_dwarf_source_path(
            &source,
            directory.as_deref(),
            compilation_directory.as_deref(),
        ),
        line,
        column,
    })
}

/// Resolve a DWARF file entry without touching the declared source path.
///
/// DWARF line programs can spell a file relative to an include directory or
/// compilation directory. The path is only normalized as metadata for later
/// matching; this backend never opens it.
///
/// Joined by the conventions of the object being read rather than those of the
/// machine reading it. The path is a string an ELF carries, so the same
/// artifact has to resolve to the same source path on every host: reading it
/// through the local path type would spell one artifact two ways and file the
/// same symbol under two sources.
fn resolve_dwarf_source_path(
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

/// Copy section, read-only-data, and relocation facts into format-neutral IR.
fn collect_sections(file: &object::File<'_>, ir: &mut ArtifactIr) -> Result<(), ArtifactError> {
    for section in file.sections() {
        let (offset, size) = section.file_range().unwrap_or((0, 0));
        ir.sections.push(ArtifactSection {
            name: section.name().ok().map(str::to_owned),
            offset,
            size,
            executable: section.kind() == SectionKind::Text,
        });
        if section.kind() == SectionKind::ReadOnlyData {
            let data = section
                .data()
                .map_err(|error| malformed(error.to_string()))?;
            if !data.is_empty() {
                ir.data_segments.push(ArtifactDataSegment {
                    fingerprint: data_fingerprint(section.name().ok(), data),
                    section: u32::try_from(section.index().0).ok(),
                    offset,
                    bytes: data.to_vec(),
                });
            }
        }
        for (relocation_offset, relocation) in section.relocations() {
            ir.relocations.push(ArtifactRelocation {
                section: u32::try_from(section.index().0).ok(),
                offset: offset.saturating_add(relocation_offset),
                kind: format!("{:?}", relocation.kind()),
                target: relocation_target_name(file, relocation.target()),
            });
        }
    }
    Ok(())
}

/// Keep a relocation's parser-supplied target as display evidence only.
fn relocation_target_name(file: &object::File<'_>, target: RelocationTarget) -> Option<String> {
    let RelocationTarget::Symbol(index) = target else {
        return None;
    };
    file.symbol_by_index(index)
        .ok()
        .and_then(|symbol| symbol.name().ok())
        .filter(|name| !name.is_empty())
        .map(demangle)
}

/// Add one explicitly inferred region per executable section of a stripped ELF.
fn infer_text_regions(file: &object::File<'_>, ir: &mut ArtifactIr) -> Result<(), ArtifactError> {
    // A stripped image has no trustworthy function boundaries. Keep each text
    // section as one inferred region rather than reporting no code or
    // inventing function names.
    for section in file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
    {
        let data = section
            .data()
            .map_err(|error| malformed(error.to_string()))?;
        if data.is_empty() {
            continue;
        }
        let (offset, _) = section.file_range().unwrap_or((0, 0));
        ir.symbols.push(ArtifactSymbol {
            fingerprint: symbol_fingerprint(
                None,
                section.name().ok(),
                normalize_x86(data, file.architecture()).as_ref(),
                data,
            ),
            name: None,
            exported: false,
            section: u32::try_from(section.index().0).ok(),
            offset,
            size: data.len() as u64,
            size_inferred: true,
            code: data.to_vec(),
            normalized: normalize_x86(data, file.architecture()),
            inline_stack: Vec::new(),
        });
    }
    Ok(())
}

fn demangle(name: &str) -> String {
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        return format!("{symbol:#}");
    }
    cpp_demangle::Symbol::new(name.as_bytes())
        .ok()
        .and_then(|symbol| symbol.demangle().ok())
        .unwrap_or_else(|| name.to_owned())
}

fn normalize_x86(code: &[u8], architecture: Architecture) -> Option<NormalizedInstructions> {
    let bitness = match architecture {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return None,
    };
    let mut decoder = Decoder::with_ip(bitness, code, 0, DecoderOptions::NONE);
    let mut normalized = Vec::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return None;
        }
        normalized.extend((instruction.code() as u32).to_le_bytes());
        normalized.push(u8::try_from(instruction.op_count()).ok()?);
        for operand in 0..instruction.op_count() {
            let kind = instruction.op_kind(operand);
            normalized.push(kind as u8);
            if kind == OpKind::Memory {
                // Register choices and immediate displacements are not kept;
                // address width and scale preserve the operand's shape.
                normalized.push(instruction.memory_size() as u8);
                normalized.push(u8::try_from(instruction.memory_index_scale()).ok()?);
                normalized.push(u8::try_from(instruction.memory_displ_size()).ok()?);
            }
        }
    }
    Some(NormalizedInstructions {
        version: ELF_NORMALIZATION_VERSION.to_owned(),
        bytes: normalized,
    })
}

fn record_x86_direct_calls(
    file: &object::File<'_>,
    symbols: &[ArtifactSymbol],
    fingerprints: &HashMap<object::SymbolIndex, Option<ArtifactFingerprint>>,
    addresses: &HashMap<u64, ArtifactFingerprint>,
    ir: &mut ArtifactIr,
) -> Result<(), ArtifactError> {
    if !matches!(
        file.architecture(),
        Architecture::I386 | Architecture::X86_64
    ) {
        return Ok(());
    }
    for section in file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
    {
        let (section_offset, _) = section.file_range().unwrap_or((0, 0));
        let section_index = u32::try_from(section.index().0).ok();
        let data = section
            .data()
            .map_err(|error| malformed(error.to_string()))?;
        let mut relocated_call_opcodes = HashSet::new();
        for (offset, relocation) in section.relocations() {
            if !matches!(
                relocation.kind(),
                RelocationKind::Relative | RelocationKind::PltRelative
            ) {
                continue;
            }
            let Ok(offset) = usize::try_from(offset) else {
                continue;
            };
            if offset == 0 || data.get(offset - 1) != Some(&0xe8) {
                continue;
            }
            relocated_call_opcodes.insert(offset - 1);
            let Some(caller) = symbols.iter().find(|symbol| {
                symbol.section == section_index
                    && section_offset.saturating_add(offset as u64) >= symbol.offset
                    && section_offset.saturating_add(offset as u64)
                        < symbol.offset.saturating_add(symbol.size)
            }) else {
                continue;
            };
            let (target, unresolved) = match relocation.target() {
                RelocationTarget::Symbol(index) => fingerprints
                    .get(&index)
                    .and_then(|value| *value)
                    .map_or((None, Some(UnresolvedCall::ExternalImport)), |target| {
                        (Some(target), None)
                    }),
                RelocationTarget::Section(_) | RelocationTarget::Absolute => {
                    (None, Some(UnresolvedCall::MissingRelocation))
                }
                _ => (None, Some(UnresolvedCall::MissingRelocation)),
            };
            ir.calls.push(ArtifactCall {
                caller: caller.fingerprint,
                target,
                unresolved,
            });
        }
        for offset in 0..data.len().saturating_sub(4) {
            if data[offset] != 0xe8 || relocated_call_opcodes.contains(&offset) {
                continue;
            }
            let Some(displacement) = data
                .get(offset + 1..offset + 5)
                .and_then(|bytes| bytes.try_into().ok())
                .map(i32::from_le_bytes)
            else {
                continue;
            };
            let Some(target_address) = section
                .address()
                .checked_add(offset as u64)
                .and_then(|address| address.checked_add(5))
                .and_then(|address| address.checked_add_signed(i64::from(displacement)))
            else {
                continue;
            };
            let Some(caller) = symbols.iter().find(|symbol| {
                symbol.section == section_index
                    && section_offset.saturating_add(offset as u64) >= symbol.offset
                    && section_offset.saturating_add(offset as u64)
                        < symbol.offset.saturating_add(symbol.size)
            }) else {
                continue;
            };
            let target = addresses.get(&target_address).copied();
            ir.calls.push(ArtifactCall {
                caller: caller.fingerprint,
                target,
                unresolved: target
                    .is_none()
                    .then_some(UnresolvedCall::MissingRelocation),
            });
        }
    }
    Ok(())
}

fn data_fingerprint(section: Option<&str>, bytes: &[u8]) -> ArtifactFingerprint {
    let section = section.unwrap_or("");
    let mut identity = Vec::new();
    identity.extend((section.len() as u64).to_le_bytes());
    identity.extend(section.as_bytes());
    identity.extend(bytes);
    ArtifactFingerprint::from_content("elf-data", &identity)
}

fn symbol_fingerprint(
    name: Option<&str>,
    section: Option<&str>,
    normalized: Option<&NormalizedInstructions>,
    code: &[u8],
) -> ArtifactFingerprint {
    let mut identity = Vec::new();
    let section = section.unwrap_or("");
    identity.extend((section.len() as u64).to_le_bytes());
    identity.extend(section.as_bytes());
    let name = name.unwrap_or("");
    identity.extend((name.len() as u64).to_le_bytes());
    identity.extend(name.as_bytes());
    if let Some(normalized) = normalized {
        identity.push(1);
        identity.extend((normalized.version.len() as u64).to_le_bytes());
        identity.extend(normalized.version.as_bytes());
        identity.extend(&normalized.bytes);
    } else {
        // Unsupported architectures retain exact-code identity rather than
        // claiming a normalized relationship that the backend did not
        // establish.
        identity.push(0);
        identity.extend(code);
    }
    ArtifactFingerprint::from_content("elf-symbol", &identity)
}

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::Elf,
        message,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use object::write::{
        Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection,
    };
    use object::{
        Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags,
        RelocationKind, SymbolFlags, SymbolScope,
    };
    use proptest::prelude::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    fn fixture() -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
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
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
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
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
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
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
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
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
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
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        object.append_section_data(text, &[0x90, 0xc3], 1);
        object.write().expect("write stripped ELF fixture")
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
            include_str!("../tests/golden/minimal-ir-v1.json").trim_end()
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
            resolve_dwarf_source_path("src/main.cpp", None, Some("/work/tree")),
            "/work/tree/src/main.cpp"
        );
        assert_eq!(
            resolve_dwarf_source_path("header.hpp", Some("include"), Some("/work/tree")),
            "/work/tree/include/header.hpp"
        );
        assert_eq!(
            resolve_dwarf_source_path("entry.cpp", Some("/other/build"), Some("/work/tree")),
            "/other/build/entry.cpp"
        );
        assert_eq!(
            resolve_dwarf_source_path("/outside/entry.cpp", Some("include"), Some("/work/tree")),
            "/outside/entry.cpp"
        );
        // A directory already ending in a separator does not gain a second one.
        // Producers write it both ways, and the same source spelled two ways
        // would be two sources to everything downstream that matches on it.
        assert_eq!(
            resolve_dwarf_source_path("src/main.cpp", None, Some("/work/tree/")),
            "/work/tree/src/main.cpp"
        );
        assert_eq!(
            resolve_dwarf_source_path("header.hpp", Some("include/"), Some("/work/tree/")),
            "/work/tree/include/header.hpp"
        );
    }
}
