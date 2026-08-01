//! ELF implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the artifact.

use codehelion_artifact::dwarf::attach_dwarf_frames;
use codehelion_artifact::symbols::demangle;
use codehelion_artifact::x86::{X86_NORMALIZATION_VERSION, normalize_x86};
use codehelion_artifact::{
    ArtifactBackend, ArtifactCall, ArtifactCapabilities, ArtifactDataSegment, ArtifactError,
    ArtifactFingerprint, ArtifactFormat, ArtifactImport, ArtifactImportKind, ArtifactIr,
    ArtifactRelocation, ArtifactSection, ArtifactSymbol, NormalizedInstructions, UnresolvedCall,
};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use object::{
    Architecture, Endianness, Object, ObjectSection, ObjectSymbol, RelocationKind,
    RelocationTarget, SectionKind, SymbolKind,
};
use std::collections::{BTreeSet, HashMap};

/// Parser backend for ELF artifacts.
#[derive(Debug, Default, Clone, Copy)]
pub struct ElfBackend;

/// Version of the shared x86 instruction-shape normalization representation.
pub const ELF_NORMALIZATION_VERSION: &str = X86_NORMALIZATION_VERSION;

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
        for section in file
            .sections()
            .filter(|section| section.kind() == SectionKind::Text)
        {
            let section_index = section.index();
            let data = section
                .data()
                .map_err(|error| malformed(error.to_string()))?;
            let mut symbols: Vec<_> = file
                .symbols()
                .filter(|symbol| {
                    symbol.kind() == SymbolKind::Text
                        && !symbol.is_undefined()
                        && symbol.section_index() == Some(section_index)
                })
                .collect();
            symbols.sort_by_key(ObjectSymbol::address);
            for (index, symbol) in symbols.iter().enumerate() {
                let Some(relative) = symbol.address().checked_sub(section.address()) else {
                    continue;
                };
                let next_address = symbols[index.saturating_add(1)..]
                    .iter()
                    .map(ObjectSymbol::address)
                    .find(|address| *address > symbol.address())
                    .unwrap_or_else(|| section.address().saturating_add(data.len() as u64));
                let size = if symbol.size() == 0 {
                    next_address.saturating_sub(symbol.address())
                } else {
                    symbol.size()
                };
                let Ok(start) = usize::try_from(relative) else {
                    continue;
                };
                let Ok(size_usize) = usize::try_from(size) else {
                    continue;
                };
                let Some(code) = data.get(start..start.saturating_add(size_usize)) else {
                    continue;
                };
                if code.is_empty() {
                    continue;
                }
                let (section_offset, _) = section.file_range().unwrap_or((0, 0));
                let name = symbol
                    .name()
                    .ok()
                    .filter(|name| !name.is_empty())
                    .map(demangle);
                let normalized = normalize_x86(code, file.architecture());
                let fingerprint = symbol_fingerprint(
                    name.as_deref(),
                    section.name().ok(),
                    normalized.as_ref(),
                    code,
                );
                ir.symbols.push(ArtifactSymbol {
                    fingerprint,
                    name,
                    exported: symbol.is_global(),
                    section: u32::try_from(section_index.0).ok(),
                    offset: section_offset.saturating_add(relative),
                    size,
                    size_inferred: symbol.size() == 0,
                    code: code.to_vec(),
                    normalized,
                    inline_stack: Vec::new(),
                });
                symbol_fingerprints.insert(symbol.index(), Some(fingerprint));
                symbol_addresses
                    .entry(symbol.address())
                    .or_insert(fingerprint);
                symbol_addresses_by_fingerprint.insert(fingerprint, (symbol.address(), size));
            }
        }
        if ir.symbols.is_empty() {
            infer_text_regions(&file, &mut ir)?;
        }
        record_entry_point(file.entry(), &symbol_addresses, &mut ir);
        record_init_fini_roots(&file, &symbol_fingerprints, &symbol_addresses, &mut ir);
        ir.calls = x86_direct_calls(&file, &ir.symbols, &symbol_fingerprints, &symbol_addresses);
        attach_dwarf_frames(
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
        let normalized = normalize_x86(data, file.architecture());
        ir.symbols.push(ArtifactSymbol {
            fingerprint: symbol_fingerprint(None, section.name().ok(), normalized.as_ref(), data),
            name: None,
            exported: false,
            section: u32::try_from(section.index().0).ok(),
            offset,
            size: data.len() as u64,
            size_inferred: true,
            code: data.to_vec(),
            normalized,
            inline_stack: Vec::new(),
        });
    }
    Ok(())
}

fn x86_direct_calls(
    file: &object::File<'_>,
    symbols: &[ArtifactSymbol],
    fingerprints: &HashMap<object::SymbolIndex, Option<ArtifactFingerprint>>,
    addresses: &HashMap<u64, ArtifactFingerprint>,
) -> Vec<ArtifactCall> {
    let bitness = match file.architecture() {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return Vec::new(),
    };
    if symbols.is_empty() {
        return Vec::new();
    }
    let mut calls = Vec::new();
    for section in file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
    {
        let (section_offset, _) = section.file_range().unwrap_or((0, 0));
        let section_index = u32::try_from(section.index().0).ok();
        let mut relocation_targets = HashMap::new();
        for (offset, relocation) in section.relocations() {
            if !matches!(
                relocation.kind(),
                RelocationKind::Relative | RelocationKind::PltRelative
            ) {
                continue;
            }
            relocation_targets.insert(offset, relocation.target());
        }
        for caller in symbols
            .iter()
            .filter(|symbol| symbol.section == section_index)
        {
            let Some(relative) = caller.offset.checked_sub(section_offset) else {
                continue;
            };
            let Some(ip) = section.address().checked_add(relative) else {
                continue;
            };
            let mut decoder = Decoder::with_ip(bitness, &caller.code, ip, DecoderOptions::NONE);
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.is_invalid()
                    || instruction.mnemonic() != Mnemonic::Call
                    || !matches!(
                        instruction.op0_kind(),
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                    )
                {
                    continue;
                }
                let Some(operand_offset) = instruction
                    .ip()
                    .checked_sub(section.address())
                    .and_then(|offset| offset.checked_add(1))
                else {
                    continue;
                };
                let (target, unresolved) = relocation_targets.get(&operand_offset).map_or_else(
                    || {
                        let target = addresses.get(&instruction.near_branch_target()).copied();
                        (
                            target,
                            target
                                .is_none()
                                .then_some(UnresolvedCall::MissingRelocation),
                        )
                    },
                    |relocation_target| match relocation_target {
                        RelocationTarget::Symbol(index) => fingerprints
                            .get(index)
                            .and_then(|value| *value)
                            .map_or((None, Some(UnresolvedCall::ExternalImport)), |target| {
                                (Some(target), None)
                            }),
                        RelocationTarget::Section(_) | RelocationTarget::Absolute => {
                            (None, Some(UnresolvedCall::MissingRelocation))
                        }
                        _ => (None, Some(UnresolvedCall::MissingRelocation)),
                    },
                );
                calls.push(ArtifactCall {
                    caller: caller.fingerprint,
                    target,
                    unresolved,
                });
            }
        }
    }
    calls
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
mod tests;
