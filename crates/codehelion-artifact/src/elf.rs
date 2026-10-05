//! ELF implementation of the codehelion artifact backend boundary.
//!
//! The backend reads bytes through the safe `object` API and never maps or
//! executes the artifact.

use crate::dwarf::{DwarfBudget, attach_dwarf_frames};
use crate::identity::{PositionalCall, assign_identities};
use crate::native::{
    collect_sections, collect_text_symbol_ranges, collect_undefined_imports, join_addresses,
};
use crate::support::format_support;
use crate::x86::X86_NORMALIZATION_VERSION;
use crate::{
    ArtifactBackend, ArtifactCapabilities, ArtifactError, ArtifactFormat, ArtifactIr,
    ArtifactSymbol, UnresolvedCall,
};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
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
        self.parse_within(bytes, debug_companion, DwarfBudget::default())
    }

    /// The same parse, under bounds an operator narrowed.
    ///
    /// Debug information describes address ranges and line rows far more
    /// compactly than the structures a reader builds from them, so the number
    /// of bytes accepted does not on its own bound what they expand into.
    /// This is where an operator's ceiling reaches those structures.
    ///
    /// # Errors
    ///
    /// The same as [`Self::parse_with_debug_companion`].
    #[allow(
        clippy::too_many_lines,
        reason = "parsing one artifact keeps all fallible format reads in one transaction"
    )]
    pub fn parse_within(
        &self,
        bytes: &[u8],
        debug_companion: Option<&[u8]>,
        budget: DwarfBudget,
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
        // Joins resolve to symbol positions, so copies sharing a fingerprint
        // stay apart until identities are assigned.
        let mut symbol_positions = HashMap::new();
        let mut symbol_addresses = HashMap::new();
        let mut symbol_addresses_by_section = HashMap::new();
        collect_sections(&file, &mut ir).map_err(|error| malformed(error.to_string()))?;
        collect_undefined_imports(file.symbols().chain(file.dynamic_symbols()), &mut ir);
        let supports_global_address_join = file.kind() != ObjectKind::Relocatable;
        let text = collect_text_symbol_ranges(&file, &mut ir)
            .map_err(|error| malformed(error.to_string()))?;
        for symbol in &text.symbols {
            symbol_positions.insert(symbol.index, symbol.position);
            symbol_addresses_by_section.insert((symbol.section, symbol.address), symbol.position);
            if supports_global_address_join {
                symbol_addresses
                    .entry(symbol.address)
                    .or_insert(symbol.position);
            }
        }
        let entry = entry_root(file.entry(), &symbol_addresses);
        let init_fini = init_fini_roots(&file, &symbol_positions, &symbol_addresses);
        let transfers = x86_transfers(
            &file,
            &ir.symbols,
            &symbol_positions,
            &symbol_addresses_by_section,
            &symbol_addresses,
        );
        let roots: BTreeSet<usize> = entry
            .iter()
            .chain(&init_fini)
            .chain(&transfers.address_taken)
            .copied()
            .collect();
        ir.calls = assign_identities(&mut ir.symbols, &roots, transfers.calls);
        let fingerprints = |positions: &BTreeSet<usize>| -> BTreeSet<_> {
            positions
                .iter()
                .map(|position| ir.symbols[*position].fingerprint)
                .collect()
        };
        let init_fini = fingerprints(&init_fini);
        let address_taken = fingerprints(&transfers.address_taken);
        if let Some(entry) = entry {
            ir.entry_points.push(ir.symbols[entry].fingerprint);
        }
        let existing: BTreeSet<_> = ir.entry_points.iter().copied().collect();
        ir.entry_points.extend(
            init_fini
                .into_iter()
                .filter(|fingerprint| !existing.contains(fingerprint)),
        );
        ir.indirect_references.extend(address_taken);
        attach_dwarf_frames(
            debug_file.as_ref().unwrap_or(&file),
            &join_addresses(&text.addresses, &ir.symbols),
            &mut ir,
            budget,
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

/// The symbol an ELF entry address resolves to, by position.
///
/// A zero entry address is the conventional absence marker for relocatable
/// objects. Addresses are lookup evidence only and never become part of IR
/// identity.
fn entry_root(entry_address: u64, addresses: &HashMap<u64, usize>) -> Option<usize> {
    (entry_address != 0)
        .then(|| addresses.get(&entry_address).copied())
        .flatten()
}

/// Treat constructor and destructor arrays as conservative local roots.
///
/// A relocation in either array is loader evidence that the target can run
/// even without a normal call edge or external export. The section and symbol
/// indexes are used only while parsing; the IR records the stable fingerprint.
fn init_fini_roots(
    file: &object::File<'_>,
    positions: &HashMap<object::SymbolIndex, usize>,
    addresses: &HashMap<u64, usize>,
) -> BTreeSet<usize> {
    let mut roots = BTreeSet::new();
    for section in file.sections() {
        if !matches!(section.name().ok(), Some(".init_array" | ".fini_array")) {
            continue;
        }
        for (_, relocation) in section.relocations() {
            if let RelocationTarget::Symbol(index) = relocation.target()
                && let Some(position) = positions.get(&index)
            {
                roots.insert(*position);
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
    roots
}

/// Resolve pointer-width values retained in a linked init/fini array.
fn pointer_roots(
    bytes: &[u8],
    is_64: bool,
    endianness: Endianness,
    addresses: &HashMap<u64, usize>,
) -> BTreeSet<usize> {
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

/// Control transfers and address-taken functions an x86 ELF's code establishes.
#[derive(Debug, Default)]
struct X86Transfers {
    /// A call or a jump that leaves the function holding it, with its target
    /// when the object names one.
    calls: Vec<PositionalCall>,
    /// Functions whose address is stored, loaded, or otherwise handed out, and
    /// which therefore run without any call edge reaching them.
    address_taken: BTreeSet<usize>,
}

/// Where one function lies in its section's address space.
#[derive(Debug, Clone, Copy)]
struct FunctionRange {
    start: u64,
    end: u64,
    position: usize,
}

/// A function by its position in the symbol list, beside its record.
type Positioned<'a> = (usize, &'a ArtifactSymbol);

/// Whether a section's pointers can name a function's address.
fn holds_function_pointers<'data>(section: &impl ObjectSection<'data>) -> bool {
    matches!(
        section.kind(),
        SectionKind::Data | SectionKind::ReadOnlyData | SectionKind::ReadOnlyDataWithRel
    ) && !matches!(section.name(), Ok(name) if name.starts_with(".eh_frame") || name.starts_with(".debug"))
}

/// What resolving a branch inside one text section needs to know about it.
struct SectionBranches<'a> {
    section: object::SectionIndex,
    address: u64,
    /// Rel32 branch operands the object relocates, by section offset.
    relocation_targets: HashMap<u64, RelocationTarget>,
    /// Functions of the section sorted by start address.
    ranges: Vec<FunctionRange>,
    positions: &'a HashMap<object::SymbolIndex, usize>,
    addresses: &'a HashMap<(object::SectionIndex, u64), usize>,
}

impl SectionBranches<'_> {
    /// Resolve a near branch to the function it enters.
    ///
    /// `inside` is the address span of the function holding the branch. A
    /// jump that stays inside it is control flow rather than a transfer, and
    /// yields neither a target nor a reason. A relocated operand the branch
    /// consumed is added to `consumed`.
    fn resolve(
        &self,
        instruction: &Instruction,
        is_jump: bool,
        inside: &std::ops::Range<u64>,
        consumed: &mut BTreeSet<u64>,
    ) -> (Option<usize>, Option<UnresolvedCall>) {
        let relocation = rel32_displacement(instruction, self.address)
            .and_then(|offset| self.relocation_targets.get(&offset).map(|t| (offset, t)));
        if let Some((offset, target)) = relocation {
            consumed.insert(offset);
            return match target {
                RelocationTarget::Symbol(index) => self
                    .positions
                    .get(index)
                    .copied()
                    .map_or((None, Some(UnresolvedCall::ExternalImport)), |target| {
                        (Some(target), None)
                    }),
                _ => (None, Some(UnresolvedCall::MissingRelocation)),
            };
        }
        let destination = instruction.near_branch_target();
        if is_jump && inside.contains(&destination) {
            return (None, None);
        }
        let target = self
            .addresses
            .get(&(self.section, destination))
            .copied()
            .or_else(|| {
                is_jump
                    .then(|| containing_function(&self.ranges, destination))
                    .flatten()
            });
        (
            target,
            target
                .is_none()
                .then_some(UnresolvedCall::MissingRelocation),
        )
    }
}

const fn is_jump(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Jmp
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jno
            | Mnemonic::Jnp
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jp
            | Mnemonic::Js
    )
}

/// Address ranges of the non-empty functions of one section, sorted by start.
fn function_ranges(
    functions: &[Positioned<'_>],
    section_address: u64,
    section_offset: u64,
) -> Vec<FunctionRange> {
    let mut ranges: Vec<_> = functions
        .iter()
        .filter(|(_, function)| !function.code.is_empty())
        .filter_map(|(position, function)| {
            let start =
                section_address.checked_add(function.offset.checked_sub(section_offset)?)?;
            let length = u64::try_from(function.code.len()).ok()?;
            Some(FunctionRange {
                start,
                end: start.saturating_add(length),
                position: *position,
            })
        })
        .collect();
    ranges.sort_by_key(|range| range.start);
    ranges
}

/// Decode one function and record the transfers and address-taking in it.
#[allow(clippy::too_many_arguments)]
fn scan_function(
    (position, caller): Positioned<'_>,
    ip: u64,
    inside: &std::ops::Range<u64>,
    bitness: u32,
    branches: &SectionBranches<'_>,
    global_addresses: &HashMap<u64, usize>,
    consumed: &mut BTreeSet<u64>,
    transfers: &mut X86Transfers,
) {
    let mut decoder = Decoder::with_ip(bitness, &caller.code, ip, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            continue;
        }
        let is_call = instruction.mnemonic() == Mnemonic::Call;
        let is_jump = is_jump(instruction.mnemonic());
        if !is_call && !is_jump {
            if !global_addresses.is_empty() {
                note_address_taken(&instruction, global_addresses, transfers);
            }
            continue;
        }
        let near = matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        );
        // A jump through a scaled table is a switch inside the function. A jump
        // through a register or a plain memory slot may be a tail call, which
        // this backend cannot name.
        if is_jump
            && !near
            && instruction.op0_kind() == OpKind::Memory
            && instruction.memory_index() != Register::None
        {
            continue;
        }
        // A call through a register, a memory operand, or a far pointer reaches
        // a callee this backend cannot name, and virtual dispatch is compiled to
        // exactly those forms. Dropping it would leave a graph that looks
        // complete while missing every edge a vtable supplies.
        let (target, unresolved) = if near {
            branches.resolve(&instruction, is_jump, inside, consumed)
        } else {
            (None, Some(UnresolvedCall::NativeIndirect))
        };
        if target.is_some() || unresolved.is_some() {
            transfers.calls.push(PositionalCall {
                caller: position,
                target,
                unresolved,
            });
        }
    }
}

fn x86_transfers(
    file: &object::File<'_>,
    symbols: &[ArtifactSymbol],
    positions: &HashMap<object::SymbolIndex, usize>,
    addresses: &HashMap<(object::SectionIndex, u64), usize>,
    global_addresses: &HashMap<u64, usize>,
) -> X86Transfers {
    let bitness = match file.architecture() {
        Architecture::I386 => 32,
        Architecture::X86_64 => 64,
        _ => return X86Transfers::default(),
    };
    if symbols.is_empty() {
        return X86Transfers::default();
    }
    let mut transfers = X86Transfers::default();
    let mut callers_by_section: HashMap<Option<u32>, Vec<Positioned<'_>>> = HashMap::new();
    for (position, symbol) in symbols.iter().enumerate() {
        callers_by_section
            .entry(symbol.section)
            .or_default()
            .push((position, symbol));
    }
    for section in file
        .sections()
        .filter(|section| section.kind() == SectionKind::Text)
    {
        let (section_offset, _) = section.file_range().unwrap_or((0, 0));
        let section_index = u32::try_from(section.index().0).ok();
        let mut section_relocations = Vec::new();
        let mut relocation_targets = HashMap::new();
        for (offset, relocation) in section.relocations() {
            section_relocations.push((offset, relocation.target()));
            if matches!(
                relocation.kind(),
                RelocationKind::Relative | RelocationKind::PltRelative
            ) {
                relocation_targets.insert(offset, relocation.target());
            }
        }
        let callers = callers_by_section
            .get(&section_index)
            .map_or(&[][..], Vec::as_slice);
        let ranges = function_ranges(callers, section.address(), section_offset);
        let branches = SectionBranches {
            section: section.index(),
            address: section.address(),
            relocation_targets,
            ranges,
            positions,
            addresses,
        };
        let mut consumed = BTreeSet::new();
        for &(position, caller) in callers {
            let Some(ip) = caller
                .offset
                .checked_sub(section_offset)
                .and_then(|relative| section.address().checked_add(relative))
            else {
                continue;
            };
            let inside = ip..ip.saturating_add(u64::try_from(caller.code.len()).unwrap_or(0));
            scan_function(
                (position, caller),
                ip,
                &inside,
                bitness,
                &branches,
                global_addresses,
                &mut consumed,
                &mut transfers,
            );
        }
        // A relocation no branch consumed hands a function's address to
        // whatever the instruction does with it.
        for (_, target) in section_relocations
            .iter()
            .filter(|(offset, _)| !consumed.contains(offset))
        {
            note_relocation_target(
                file,
                target,
                positions,
                &callers_by_section,
                &mut transfers.address_taken,
            );
        }
    }
    note_data_references(
        file,
        positions,
        &callers_by_section,
        global_addresses,
        &mut transfers.address_taken,
    );
    transfers
}

/// Record the functions that data sections and dynamic relocations point at.
fn note_data_references(
    file: &object::File<'_>,
    positions: &HashMap<object::SymbolIndex, usize>,
    callers_by_section: &HashMap<Option<u32>, Vec<Positioned<'_>>>,
    global_addresses: &HashMap<u64, usize>,
    address_taken: &mut BTreeSet<usize>,
) {
    for section in file.sections().filter(holds_function_pointers) {
        for (_, relocation) in section.relocations() {
            note_relocation_target(
                file,
                &relocation.target(),
                positions,
                callers_by_section,
                address_taken,
            );
        }
        if !global_addresses.is_empty()
            && let Ok(data) = section.data()
        {
            address_taken.extend(pointer_roots(
                data,
                file.is_64(),
                file.endianness(),
                global_addresses,
            ));
        }
    }
    if global_addresses.is_empty() {
        return;
    }
    for (_, relocation) in file.dynamic_relocations().into_iter().flatten() {
        if relocation.target() == RelocationTarget::Absolute
            && let Ok(address) = u64::try_from(relocation.addend())
            && let Some(position) = global_addresses.get(&address)
        {
            address_taken.insert(*position);
        }
    }
}

/// The function whose bytes contain `address`, among ranges sorted by start.
fn containing_function(ranges: &[FunctionRange], address: u64) -> Option<usize> {
    let after = ranges.partition_point(|range| range.start <= address);
    ranges
        .get(after.checked_sub(1)?)
        .filter(|range| address < range.end)
        .map(|range| range.position)
}

/// Record the function a relocation points at as address-taken.
///
/// A section target names no single function, so every function in a text
/// section it points into counts.
fn note_relocation_target(
    file: &object::File<'_>,
    target: &RelocationTarget,
    positions: &HashMap<object::SymbolIndex, usize>,
    callers_by_section: &HashMap<Option<u32>, Vec<Positioned<'_>>>,
    address_taken: &mut BTreeSet<usize>,
) {
    match target {
        RelocationTarget::Symbol(index) => {
            if let Some(position) = positions.get(index) {
                address_taken.insert(*position);
            }
        }
        RelocationTarget::Section(index)
            if file
                .section_by_index(*index)
                .is_ok_and(|section| section.kind() == SectionKind::Text) =>
        {
            address_taken.extend(
                callers_by_section
                    .get(&u32::try_from(index.0).ok())
                    .into_iter()
                    .flatten()
                    .map(|(position, _)| *position),
            );
        }
        _ => {}
    }
}

/// Record a function whose address an instruction of a linked image computes.
fn note_address_taken(
    instruction: &Instruction,
    addresses: &HashMap<u64, usize>,
    transfers: &mut X86Transfers,
) {
    if instruction.is_ip_rel_memory_operand()
        && let Some(position) = addresses.get(&instruction.ip_rel_memory_address())
    {
        transfers.address_taken.insert(*position);
    }
    for operand in 0..instruction.op_count() {
        if matches!(
            instruction.op_kind(operand),
            OpKind::Immediate32 | OpKind::Immediate64 | OpKind::Immediate32to64
        ) && let Some(position) = addresses.get(&instruction.immediate(operand))
        {
            transfers.address_taken.insert(*position);
        }
    }
}

/// Section offset of the displacement a relocation can land on in a near
/// branch, which is its last four bytes. A rel8 branch has none.
fn rel32_displacement(instruction: &Instruction, section_address: u64) -> Option<u64> {
    if instruction.len() < 5 {
        return None;
    }
    instruction
        .ip()
        .checked_sub(section_address)?
        .checked_add(u64::try_from(instruction.len()).ok()?)?
        .checked_sub(4)
}

const fn malformed(message: String) -> ArtifactError {
    ArtifactError::Malformed {
        format: ArtifactFormat::Elf,
        message,
    }
}

/// This build's reader for the format, the input it parses, and the magic that
/// makes arbitrary bytes look like one of its own.
#[cfg(test)]
pub(crate) fn under_test() -> crate::FormatUnderTest {
    crate::FormatUnderTest {
        backend: &ElfBackend,
        valid: tests::fixture(),
        magics: &[b"\x7fELF"],
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
