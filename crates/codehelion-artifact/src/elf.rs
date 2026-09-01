//! ELF implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the artifact.

use crate::dwarf::attach_dwarf_frames;
use crate::native::{collect_sections, collect_text_symbol_ranges, collect_undefined_imports};
use crate::support::format_support;
use crate::x86::X86_NORMALIZATION_VERSION;
use crate::{
    ArtifactBackend, ArtifactCall, ArtifactCapabilities, ArtifactError, ArtifactFingerprint,
    ArtifactFormat, ArtifactIr, ArtifactSymbol, UnresolvedCall,
};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use object::{
    Architecture, Endianness, Object, ObjectKind, ObjectSection, RelocationKind, RelocationTarget,
    SectionKind,
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
        format_support(ArtifactFormat::Elf).capabilities
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
        let mut symbol_addresses_by_section = HashMap::new();
        collect_sections(&file, &mut ir).map_err(|error| malformed(error.to_string()))?;
        collect_undefined_imports(file.symbols().chain(file.dynamic_symbols()), &mut ir);
        let supports_global_address_join = file.kind() != ObjectKind::Relocatable;
        let text = collect_text_symbol_ranges(&file, &mut ir)
            .map_err(|error| malformed(error.to_string()))?;
        for symbol in &text.symbols {
            symbol_fingerprints.insert(symbol.index, Some(symbol.fingerprint));
            symbol_addresses_by_section
                .insert((symbol.section, symbol.address), symbol.fingerprint);
            if supports_global_address_join {
                symbol_addresses
                    .entry(symbol.address)
                    .or_insert(symbol.fingerprint);
            }
        }
        record_entry_point(file.entry(), &symbol_addresses, &mut ir);
        record_init_fini_roots(&file, &symbol_fingerprints, &symbol_addresses, &mut ir);
        ir.calls = x86_direct_calls(
            &file,
            &ir.symbols,
            &symbol_fingerprints,
            &symbol_addresses_by_section,
        );
        attach_dwarf_frames(
            debug_file.as_ref().unwrap_or(&file),
            &text.addresses,
            &mut ir,
        );
        ir.capabilities = ArtifactCapabilities {
            symbols: !ir.symbols.is_empty(),
            call_graph: !ir.calls.is_empty(),
            source_mapping: !ir.source_mappings.is_empty(),
            debug_info_unreadable: ir.capabilities.debug_info_unreadable,
            normalized_duplicates: crate::x86::supports_normalized_duplicates(file.architecture()),
            independent_data_segments: false,
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
    if entry_address != 0
        && let Some(fingerprint) = addresses.get(&entry_address)
    {
        ir.entry_points.push(*fingerprint);
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
            if let RelocationTarget::Symbol(index) = relocation.target()
                && let Some(Some(fingerprint)) = fingerprints.get(&index)
            {
                roots.insert(*fingerprint);
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

fn x86_direct_calls(
    file: &object::File<'_>,
    symbols: &[ArtifactSymbol],
    fingerprints: &HashMap<object::SymbolIndex, Option<ArtifactFingerprint>>,
    addresses: &HashMap<(object::SectionIndex, u64), ArtifactFingerprint>,
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
                if instruction.is_invalid() || instruction.mnemonic() != Mnemonic::Call {
                    continue;
                }
                // A call through a register, a memory operand, or a far pointer
                // reaches a callee this backend cannot name, and virtual
                // dispatch is compiled to exactly those forms. Dropping it
                // would leave a graph that looks complete while missing every
                // edge a vtable supplies.
                let operand_offset = matches!(
                    instruction.op0_kind(),
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                )
                .then(|| {
                    instruction
                        .ip()
                        .checked_sub(section.address())
                        .and_then(|offset| offset.checked_add(1))
                });
                let (target, unresolved) = match operand_offset {
                    None => (None, Some(UnresolvedCall::NativeIndirect)),
                    // A near branch whose operand lies outside this section is
                    // a target the parser could not read, not an external one.
                    Some(None) => (None, Some(UnresolvedCall::MissingRelocation)),
                    Some(Some(operand_offset)) => {
                        relocation_targets.get(&operand_offset).map_or_else(
                            || {
                                let target = addresses
                                    .get(&(section.index(), instruction.near_branch_target()))
                                    .copied();
                                (
                                    target,
                                    target
                                        .is_none()
                                        .then_some(UnresolvedCall::MissingRelocation),
                                )
                            },
                            |relocation_target| match relocation_target {
                                RelocationTarget::Symbol(index) => {
                                    fingerprints.get(index).and_then(|value| *value).map_or(
                                        (None, Some(UnresolvedCall::ExternalImport)),
                                        |target| (Some(target), None),
                                    )
                                }
                                RelocationTarget::Section(_) | RelocationTarget::Absolute => {
                                    (None, Some(UnresolvedCall::MissingRelocation))
                                }
                                _ => (None, Some(UnresolvedCall::MissingRelocation)),
                            },
                        )
                    }
                };
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

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::Elf,
        message,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
