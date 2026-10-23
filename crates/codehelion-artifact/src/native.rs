//! Shared native-object collection helpers.

use std::collections::{BTreeMap, HashMap, HashSet};

use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

use crate::symbols::demangle;
use crate::x86::normalize_x86;
use crate::{
    ArtifactDataSegment, ArtifactFingerprint, ArtifactImport, ArtifactImportKind, ArtifactIr,
    ArtifactRelocation, ArtifactSection, ArtifactSymbol, NormalizedInstructions,
};

/// Collect undefined native-object symbols as imports.
///
/// A text symbol names a function across ELF, Mach-O, and PE/COFF. Other
/// undefined symbol kinds remain deliberately conservative. If a malformed
/// object presents the same name with conflicting kinds, `function` wins: it
/// retains the stronger parser evidence without inventing a signature.
pub fn collect_undefined_imports<'data, S>(
    symbols: impl IntoIterator<Item = S>,
    ir: &mut ArtifactIr,
) where
    S: ObjectSymbol<'data>,
{
    let mut names = BTreeMap::new();
    for symbol in symbols {
        if !symbol.is_undefined() {
            continue;
        }
        let Some(name) = symbol
            .name()
            .ok()
            .filter(|name| !name.is_empty())
            .map(demangle)
        else {
            continue;
        };
        // Mach-O and COFF do not retain a section-derived text kind for an
        // undefined external in their object symbol table. `Unknown` is the
        // corresponding native import spelling, while data remains explicit.
        let kind = if matches!(symbol.kind(), SymbolKind::Text | SymbolKind::Unknown) {
            ArtifactImportKind::Function
        } else {
            ArtifactImportKind::Other
        };
        names
            .entry(name)
            .and_modify(|existing| {
                if kind == ArtifactImportKind::Function {
                    *existing = kind;
                }
            })
            .or_insert(kind);
    }
    ir.imports
        .extend(names.into_iter().map(|(name, kind)| ArtifactImport {
            module: None,
            name: Some(name),
            kind,
        }));
}

/// Copy the section and read-only data facts common to native object formats
/// into format-neutral IR.
///
/// Relocations are recorded by [`collect_text_symbols`], which can name the
/// function a section-relative target lands in.
///
/// # Errors
///
/// Returns an object-reader error when a section's bytes cannot be read.
pub fn collect_sections(file: &object::File<'_>, ir: &mut ArtifactIr) -> Result<(), object::Error> {
    for section in file.sections() {
        let (offset, size) = section.file_range().unwrap_or((0, 0));
        ir.sections.push(ArtifactSection {
            name: section.name().ok().map(str::to_owned),
            offset,
            size,
            executable: section.kind() == object::SectionKind::Text,
        });
        if section.kind() == object::SectionKind::ReadOnlyData {
            let data = section.data()?;
            if !data.is_empty() {
                ir.data_segments.push(ArtifactDataSegment {
                    fingerprint: data_fingerprint(section.name().ok(), data),
                    section: u32::try_from(section.index().0).ok(),
                    offset,
                    bytes: data.to_vec(),
                });
            }
        }
    }
    Ok(())
}

/// Build the common native-symbol identity from unambiguous fields.
///
/// The representation includes an explicit payload kind, so a normalized
/// instruction representation cannot collide with an equal-looking raw byte
/// sequence. Each variable-length field is length-prefixed to preserve the
/// boundary between adjacent fields.
#[must_use]
pub fn symbol_fingerprint(
    name: Option<&str>,
    section: Option<&str>,
    normalized: Option<&NormalizedInstructions>,
    code: &[u8],
) -> ArtifactFingerprint {
    relocated_symbol_fingerprint(name, section, normalized, code, &[])
}

/// [`symbol_fingerprint`] with the relocations inside the symbol appended.
///
/// No relocations leaves the identity exactly as [`symbol_fingerprint`] builds
/// it, so an artifact without relocations keeps its fingerprints.
fn relocated_symbol_fingerprint(
    name: Option<&str>,
    section: Option<&str>,
    normalized: Option<&NormalizedInstructions>,
    code: &[u8],
    relocations: &[RelocationFact],
) -> ArtifactFingerprint {
    let mut identity = Vec::new();
    append_field(&mut identity, name.unwrap_or_default().as_bytes());
    append_field(&mut identity, section.unwrap_or_default().as_bytes());
    if let Some(normalized) = normalized {
        identity.push(1);
        append_field(&mut identity, normalized.version.as_bytes());
        append_field(&mut identity, &normalized.bytes);
    } else {
        identity.push(0);
        append_field(&mut identity, code);
    }
    for relocation in relocations {
        append_field(&mut identity, &relocation.offset.to_le_bytes());
        append_field(&mut identity, relocation.kind.as_bytes());
        identity.push(u8::from(relocation.target.is_some()));
        append_field(
            &mut identity,
            relocation.target.as_deref().unwrap_or_default().as_bytes(),
        );
    }
    ArtifactFingerprint::from_content("native-symbol", &identity)
}

/// Build the common native data-segment identity from its section and bytes.
#[must_use]
pub fn data_fingerprint(section: Option<&str>, data: &[u8]) -> ArtifactFingerprint {
    let mut identity = Vec::new();
    append_field(&mut identity, section.unwrap_or_default().as_bytes());
    append_field(&mut identity, data);
    ArtifactFingerprint::from_content("native-data", &identity)
}

/// Remove only conventional trailing padding from an inferred native symbol.
///
/// Explicit symbol sizes are authoritative and must not use this helper.
#[must_use]
pub fn trim_inferred_symbol_padding(code: &[u8], architecture: object::Architecture) -> &[u8] {
    crate::x86::trim_inferred_padding(code, architecture)
}

/// Ownership facts for one entry of a symbol list sorted by address, larger
/// declared sizes first among equal addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SymbolBoundary {
    /// Entry whose bytes cover this one's start, when this one is an alias.
    owner: Option<usize>,
    /// End of the bytes this entry owns; its own start when it owns none.
    end: u64,
}

/// Derive which entries own bytes and where each owned range ends.
///
/// An entry starting inside bytes an earlier owner already claims is an alias
/// owning none, so owned ranges never overlap and their total never exceeds the
/// section, whatever extents the symbol table declares. A declared size ends
/// an owner's range; otherwise the next strictly greater address, or the
/// section end, does.
fn symbol_boundaries(sorted: &[(u64, u64)], section_end: u64) -> Vec<SymbolBoundary> {
    boundaries_and_reads(sorted, section_end).0
}

/// [`symbol_boundaries`] beside the number of entries it read.
///
/// The count is what separates this from a per-symbol rescan of the section:
/// a reader that consults every earlier symbol is quadratic in the number of
/// symbols sharing a section, which a wall clock only reveals on a machine
/// that happens to be idle. Callers outside the tests drop the count.
fn boundaries_and_reads(sorted: &[(u64, u64)], section_end: u64) -> (Vec<SymbolBoundary>, usize) {
    let mut next_greater = vec![None; sorted.len()];
    let mut following = None;
    for (index, window) in sorted.windows(2).enumerate().rev() {
        if let [(address, _), (next, _)] = window
            && next > address
        {
            following = Some(*next);
        }
        if let Some(slot) = next_greater.get_mut(index) {
            *slot = following;
        }
    }
    let mut boundaries = Vec::with_capacity(sorted.len());
    let mut claimed: Option<(usize, u64)> = None;
    for (index, &(address, size)) in sorted.iter().enumerate() {
        if let Some((owner, end)) = claimed
            && address < end
        {
            boundaries.push(SymbolBoundary {
                owner: Some(owner),
                end: address,
            });
            continue;
        }
        let end = if size == 0 {
            next_greater
                .get(index)
                .copied()
                .flatten()
                .unwrap_or(section_end)
        } else {
            address.saturating_add(size)
        };
        claimed = Some((index, end));
        boundaries.push(SymbolBoundary { owner: None, end });
    }
    (boundaries, sorted.len().saturating_mul(2))
}

/// Transient native-symbol data used only by format-specific join code.
#[derive(Debug, Clone, Copy)]
pub struct NativeSymbolRange {
    /// Position of the symbol in `ArtifactIr::symbols`.
    pub position: usize,
    /// Parser-local symbol index.
    pub index: object::SymbolIndex,
    /// Parser-local section index used to disambiguate relocatable addresses.
    pub section: object::SectionIndex,
    /// Normalized parser address used only for local joins.
    pub address: u64,
    /// Retained code length.
    pub size: u64,
}

/// What a relocation target denotes once placed among the text symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedTarget {
    /// The record owning the bytes at the target, by position.
    Function(usize),
    /// A location in this text section that no record covers, or whose exact
    /// address the relocation does not state.
    UncoveredText(object::SectionIndex),
    /// A location this object defines outside its text sections.
    NotCode,
    /// A symbol this object does not define.
    Undefined,
}

/// One relocation of a section beside the target it resolved to.
#[derive(Debug, Clone, Copy)]
pub struct ResolvedRelocation {
    /// Offset of the relocated field within its section.
    pub offset: u64,
    /// Relocation kind as the object reader classified it.
    pub kind: object::RelocationKind,
    /// What the relocation points at.
    pub target: ResolvedTarget,
}

/// Bytes one record owns, as an address span of its section.
#[derive(Debug, Clone, Copy)]
struct OwnedSpan {
    start: u64,
    end: u64,
    position: usize,
}

/// One relocation inside a record, as it enters that record's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelocationFact {
    offset: u64,
    kind: String,
    target: Option<String>,
}

/// Address-keyed index over one native object's text symbols.
///
/// Built once per object. Symbol addresses are normalized here (the ARM Thumb
/// bit cleared), a symbol starting inside bytes another already owns becomes an
/// alias owning none, and every lookup — by symbol, section address, image
/// address or relocation — answers with the record that owns the bytes.
#[derive(Debug)]
pub struct SymbolIndex {
    ranges: Vec<NativeSymbolRange>,
    by_symbol: HashMap<object::SymbolIndex, usize>,
    by_start: HashMap<(object::SectionIndex, u64), usize>,
    spans: HashMap<object::SectionIndex, Vec<OwnedSpan>>,
    text_sections: HashSet<object::SectionIndex>,
    /// Present only for a linked image, whose addresses are unique.
    by_image_address: Option<HashMap<u64, usize>>,
    relocations: HashMap<object::SectionIndex, Vec<ResolvedRelocation>>,
    address_mask: u64,
    pc_relative_field_bias: bool,
}

impl SymbolIndex {
    fn new(file: &object::File<'_>) -> Self {
        let thumb = file.format() == object::BinaryFormat::Elf
            && file.architecture() == object::Architecture::Arm;
        Self {
            ranges: Vec::new(),
            by_symbol: HashMap::new(),
            by_start: HashMap::new(),
            spans: HashMap::new(),
            text_sections: HashSet::new(),
            by_image_address: (file.kind() != object::ObjectKind::Relocatable).then(HashMap::new),
            relocations: HashMap::new(),
            address_mask: if thumb { !1 } else { u64::MAX },
            pc_relative_field_bias: matches!(
                file.architecture(),
                object::Architecture::I386
                    | object::Architecture::X86_64
                    | object::Architecture::X86_64_X32
            ),
        }
    }

    /// A linked image's index holding only the given address lookups.
    #[cfg(test)]
    pub(crate) fn with_image_addresses(addresses: impl IntoIterator<Item = (u64, usize)>) -> Self {
        Self {
            ranges: Vec::new(),
            by_symbol: HashMap::new(),
            by_start: HashMap::new(),
            spans: HashMap::new(),
            text_sections: HashSet::new(),
            by_image_address: Some(addresses.into_iter().collect()),
            relocations: HashMap::new(),
            address_mask: u64::MAX,
            pc_relative_field_bias: false,
        }
    }

    /// The address of the first instruction byte a symbol or pointer value
    /// names.
    #[must_use]
    pub const fn code_address(&self, address: u64) -> u64 {
        address & self.address_mask
    }

    /// Every text symbol-table entry, owners and aliases alike.
    #[must_use]
    pub fn ranges(&self) -> &[NativeSymbolRange] {
        &self.ranges
    }

    /// The record owning the bytes of a symbol-table entry.
    #[must_use]
    pub fn symbol_owner(&self, symbol: object::SymbolIndex) -> Option<usize> {
        self.by_symbol.get(&symbol).copied()
    }

    /// The record owning the bytes a symbol of `section` starts at `address`.
    #[must_use]
    pub fn at_section_address(&self, section: object::SectionIndex, address: u64) -> Option<usize> {
        self.by_start
            .get(&(section, self.code_address(address)))
            .copied()
    }

    /// The record whose retained bytes contain `address` in `section`.
    #[must_use]
    pub fn containing(&self, section: object::SectionIndex, address: u64) -> Option<usize> {
        self.span_containing(section, address)
            .map(|span| span.position)
    }

    /// The record owning the bytes a symbol starts at in a linked image.
    #[must_use]
    pub fn at_image_address(&self, address: u64) -> Option<usize> {
        self.by_image_address
            .as_ref()?
            .get(&self.code_address(address))
            .copied()
    }

    /// Whether image addresses identify symbols, which holds for a linked
    /// image and not for a relocatable object.
    #[must_use]
    pub fn has_image_addresses(&self) -> bool {
        self.by_image_address
            .as_ref()
            .is_some_and(|addresses| !addresses.is_empty())
    }

    /// Records owning bytes in `section`, by position.
    pub fn section_owners(
        &self,
        section: object::SectionIndex,
    ) -> impl Iterator<Item = usize> + '_ {
        self.spans
            .get(&section)
            .into_iter()
            .flatten()
            .map(|span| span.position)
    }

    /// Relocations of `section` with their resolved targets, by offset.
    #[must_use]
    pub fn relocations_in(&self, section: object::SectionIndex) -> &[ResolvedRelocation] {
        self.relocations.get(&section).map_or(&[], Vec::as_slice)
    }

    fn span_containing(&self, section: object::SectionIndex, address: u64) -> Option<OwnedSpan> {
        let spans = self.spans.get(&section)?;
        let after = spans.partition_point(|span| span.start <= address);
        spans
            .get(after.checked_sub(1)?)
            .filter(|span| address < span.end)
            .copied()
    }

    /// Place a relocation target among the text symbols.
    ///
    /// A named symbol resolves to its owner. A section symbol, a local label
    /// or a section target resolves through its address plus the addend, and
    /// a PC-relative x86 field adds back its own width, which the addend
    /// subtracts to reach the end of the instruction.
    fn resolve_relocation(
        &self,
        file: &object::File<'_>,
        relocation: &object::Relocation,
    ) -> ResolvedTarget {
        let (section, address) = match relocation.target() {
            object::RelocationTarget::Symbol(index) => {
                if let Some(owner) = self.symbol_owner(index) {
                    return ResolvedTarget::Function(owner);
                }
                let Ok(symbol) = file.symbol_by_index(index) else {
                    return ResolvedTarget::Undefined;
                };
                if symbol.is_undefined() {
                    return ResolvedTarget::Undefined;
                }
                let Some(section) = symbol.section_index() else {
                    return ResolvedTarget::NotCode;
                };
                (section, self.code_address(symbol.address()))
            }
            object::RelocationTarget::Section(section) => (
                section,
                file.section_by_index(section)
                    .map_or(0, |section| section.address()),
            ),
            _ => return ResolvedTarget::NotCode,
        };
        if !self.text_sections.contains(&section) {
            return ResolvedTarget::NotCode;
        }
        if relocation.has_implicit_addend() {
            return ResolvedTarget::UncoveredText(section);
        }
        let bias = if self.pc_relative_field_bias
            && matches!(
                relocation.kind(),
                object::RelocationKind::Relative | object::RelocationKind::PltRelative
            ) {
            u64::from(relocation.size() / 8)
        } else {
            0
        };
        let target = address
            .wrapping_add_signed(relocation.addend())
            .wrapping_add(bias);
        self.containing(section, target).map_or(
            ResolvedTarget::UncoveredText(section),
            ResolvedTarget::Function,
        )
    }
}

impl IntoIterator for SymbolIndex {
    type Item = NativeSymbolRange;
    type IntoIter = std::vec::IntoIter<NativeSymbolRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.into_iter()
    }
}

/// Collect text symbols using the shared native identity and boundary rules,
/// then record every section's relocations against them.
///
/// A relocation's resolved target names it in the IR and, for one inside a
/// record, enters that record's identity: in a relocatable object the
/// relocated field is a placeholder, so equal bytes do not mean equal code.
///
/// # Errors
///
/// Returns an error when a text section cannot be read.
pub fn collect_text_symbols(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<SymbolIndex, object::Error> {
    let mut index = SymbolIndex::new(file);
    let mut by_section: HashMap<_, Vec<_>> = HashMap::new();
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text || symbol.is_undefined() {
            continue;
        }
        if let Some(section_index) = symbol.section_index() {
            by_section.entry(section_index).or_default().push(symbol);
        }
    }
    let mut identities = Vec::new();
    for section in file
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
    {
        let symbols = by_section.remove(&section.index()).unwrap_or_default();
        identities.extend(index_section(file, &section, symbols, &mut index, ir)?);
    }
    let facts = record_relocations(file, &mut index, ir);
    for (position, fingerprint_name) in identities {
        let (Some(facts), Some(symbol)) = (facts.get(&position), ir.symbols.get_mut(position))
        else {
            continue;
        };
        symbol.fingerprint = relocated_symbol_fingerprint(
            fingerprint_name.as_deref(),
            Some("text"),
            symbol.normalized.as_ref(),
            &symbol.code,
            facts,
        );
    }
    Ok(index)
}

/// Append one text section's symbol records and index them, returning each
/// record's position beside the name its fingerprint uses.
fn index_section<'data>(
    file: &object::File<'data>,
    section: &object::Section<'data, '_>,
    symbols: Vec<object::Symbol<'data, '_>>,
    index: &mut SymbolIndex,
    ir: &mut ArtifactIr,
) -> Result<Vec<(usize, Option<String>)>, object::Error> {
    let mut identities = Vec::with_capacity(symbols.len());
    let section_index = section.index();
    index.text_sections.insert(section_index);
    let data = section.data()?;
    let (section_offset, _) = section.file_range().unwrap_or((0, 0));
    let section_start = section.address();
    let section_end = section_start.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    // A symbol whose start or declared end lies outside its section names
    // no bytes of it.
    let mut symbols: Vec<_> = symbols
        .into_iter()
        .map(|symbol| (index.code_address(symbol.address()), symbol))
        .filter(|(address, symbol)| {
            *address >= section_start && address.saturating_add(symbol.size()) <= section_end
        })
        .collect();
    symbols.sort_by_key(|(address, symbol)| (*address, std::cmp::Reverse(symbol.size())));
    let boundaries = symbol_boundaries(
        &symbols
            .iter()
            .map(|(address, symbol)| (*address, symbol.size()))
            .collect::<Vec<_>>(),
        section_end,
    );
    let mut positions = Vec::with_capacity(symbols.len());
    let mut spans = Vec::new();
    for ((address, symbol), boundary) in symbols.iter().zip(boundaries) {
        let relative = address.saturating_sub(section_start);
        let (Ok(start), Ok(length)) = (
            usize::try_from(relative),
            usize::try_from(boundary.end.saturating_sub(*address)),
        ) else {
            positions.push(None);
            continue;
        };
        let Some(raw) = data.get(start..start.saturating_add(length)) else {
            positions.push(None);
            continue;
        };
        let code = if symbol.size() == 0 {
            trim_inferred_symbol_padding(raw, file.architecture())
        } else {
            raw
        };
        let (name, fingerprint_name) = symbol_names(file, symbol);
        let normalized = normalize_x86(code, file.architecture());
        let fingerprint = symbol_fingerprint(
            fingerprint_name.as_deref(),
            Some("text"),
            normalized.as_ref(),
            code,
        );
        let size = u64::try_from(code.len()).unwrap_or(u64::MAX);
        let position = ir.symbols.len();
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
            body_fingerprint: None,
            inline_stack: Vec::new(),
            content_fingerprint: None,
            identity_by_order: false,
        });
        let owner = boundary
            .owner
            .and_then(|owner| positions.get(owner).copied().flatten())
            .unwrap_or(position);
        positions.push(Some(position));
        index.by_symbol.insert(symbol.index(), owner);
        index
            .by_start
            .entry((section_index, *address))
            .or_insert(owner);
        if let Some(image) = &mut index.by_image_address {
            image.entry(*address).or_insert(owner);
        }
        if owner == position && size != 0 {
            spans.push(OwnedSpan {
                start: *address,
                end: address.saturating_add(size),
                position,
            });
        }
        index.ranges.push(NativeSymbolRange {
            position,
            index: symbol.index(),
            section: section_index,
            address: *address,
            size,
        });
        identities.push((position, fingerprint_name));
    }
    index.spans.insert(section_index, spans);
    Ok(identities)
}

/// A symbol's display name beside the name its fingerprint uses, which drops
/// the Mach-O leading underscore.
fn symbol_names(
    file: &object::File<'_>,
    symbol: &object::Symbol<'_, '_>,
) -> (Option<String>, Option<String>) {
    let raw_name = symbol.name().ok().filter(|name| !name.is_empty());
    let fingerprint_name = raw_name.map(|name| {
        let canonical = if file.format() == object::BinaryFormat::MachO {
            name.strip_prefix('_').unwrap_or(name)
        } else {
            name
        };
        demangle(canonical)
    });
    (raw_name.map(demangle), fingerprint_name)
}

/// Resolve every section's relocations once, record them in the IR, and
/// return the relocations each code record holds, by position.
fn record_relocations(
    file: &object::File<'_>,
    index: &mut SymbolIndex,
    ir: &mut ArtifactIr,
) -> HashMap<usize, Vec<RelocationFact>> {
    let mut facts: HashMap<usize, Vec<RelocationFact>> = HashMap::new();
    for section in file.sections() {
        let section_index = section.index();
        let (section_offset, _) = section.file_range().unwrap_or((0, 0));
        let is_text = index.text_sections.contains(&section_index);
        let mut resolved = Vec::new();
        for (offset, relocation) in section.relocations() {
            let target = index.resolve_relocation(file, &relocation);
            let kind = format!("{:?}", relocation.kind());
            let name = relocation_target_name(file, &relocation, target, &ir.symbols);
            if is_text
                && let Some(span) =
                    index.span_containing(section_index, section.address().saturating_add(offset))
            {
                facts
                    .entry(span.position)
                    .or_default()
                    .push(RelocationFact {
                        offset: section
                            .address()
                            .saturating_add(offset)
                            .saturating_sub(span.start),
                        kind: kind.clone(),
                        target: name.clone(),
                    });
            }
            ir.relocations.push(ArtifactRelocation {
                section: u32::try_from(section_index.0).ok(),
                offset: section_offset.saturating_add(offset),
                kind,
                target: name,
            });
            resolved.push(ResolvedRelocation {
                offset,
                kind: relocation.kind(),
                target,
            });
        }
        if !resolved.is_empty() {
            resolved.sort_by_key(|relocation| relocation.offset);
            index.relocations.insert(section_index, resolved);
        }
    }
    facts
}

/// Every code record of a native object with the address that joins it to
/// debug information.
#[derive(Debug)]
pub struct NativeTextSymbols {
    /// Symbol-table entries and their lookups, empty for an object without
    /// code symbols.
    pub index: SymbolIndex,
    /// Position, join address and retained length of each appended code
    /// record, whether it came from the symbol table or an inferred region.
    pub addresses: Vec<(usize, u64, u64)>,
}

/// Collect a native object's code records, inferring one region per text
/// section when the object carries no code symbols.
///
/// Both origins land in `addresses`, so a debug join reaches every record the
/// IR holds instead of only the named ones — which is exactly the stripped
/// image whose separate debug file is the only source evidence there is. The
/// addresses are transient join evidence and never become identities.
///
/// # Errors
///
/// Returns an object-reader error when a text section cannot be read.
pub fn collect_text_symbol_ranges(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<NativeTextSymbols, object::Error> {
    let index = collect_text_symbols(file, ir)?;
    let mut addresses: Vec<_> = index
        .ranges()
        .iter()
        .map(|range| (range.position, range.address, range.size))
        .collect();
    if ir.symbols.is_empty() {
        addresses.extend(infer_text_regions(
            file,
            ir,
            |section, normalized, data| symbol_fingerprint(None, section, normalized, data),
        )?);
    }
    Ok(NativeTextSymbols { index, addresses })
}

/// Key code records' join addresses by the fingerprints `symbols` now carry.
///
/// Built only once identities are assigned, so every copy keeps its own key.
#[must_use]
pub fn join_addresses(
    addresses: &[(usize, u64, u64)],
    symbols: &[ArtifactSymbol],
) -> HashMap<ArtifactFingerprint, (u64, u64)> {
    addresses
        .iter()
        .map(|(position, address, size)| (symbols[*position].fingerprint, (*address, *size)))
        .collect()
}

fn append_field(identity: &mut Vec<u8>, value: &[u8]) {
    identity.extend(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    identity.extend(value);
}

/// Name a relocation target: a named symbol by its name, a section-relative
/// target by the function it resolved to, otherwise by section and addend.
fn relocation_target_name(
    file: &object::File<'_>,
    relocation: &object::Relocation,
    target: ResolvedTarget,
    symbols: &[ArtifactSymbol],
) -> Option<String> {
    let symbol = match relocation.target() {
        object::RelocationTarget::Symbol(index) => file.symbol_by_index(index).ok(),
        _ => None,
    };
    if let Some(name) = symbol
        .as_ref()
        .filter(|symbol| symbol.kind() != SymbolKind::Section)
        .and_then(|symbol| symbol.name().ok())
        .filter(|name| !name.is_empty())
    {
        return Some(demangle(name));
    }
    if let ResolvedTarget::Function(position) = target {
        return symbols.get(position).and_then(|symbol| symbol.name.clone());
    }
    let section = match relocation.target() {
        object::RelocationTarget::Section(section) => section,
        object::RelocationTarget::Symbol(_) => symbol?.section_index()?,
        _ => return None,
    };
    let name = file.section_by_index(section).ok()?.name().ok()?.to_owned();
    Some(if relocation.has_implicit_addend() {
        name
    } else {
        format!("{name}{:+}", relocation.addend())
    })
}

/// Add one explicitly inferred region for every non-empty text section.
///
/// The caller supplies its format-domain fingerprint recipe. Each region's
/// position, address and size are returned as transient join evidence for
/// backends that can attach debug frames; they are never used as identities.
///
/// # Errors
///
/// Returns an object-reader error when an executable section cannot be read.
pub fn infer_text_regions<F>(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
    mut fingerprint: F,
) -> Result<Vec<(usize, u64, u64)>, object::Error>
where
    F: FnMut(Option<&str>, Option<&NormalizedInstructions>, &[u8]) -> ArtifactFingerprint,
{
    let mut ranges = Vec::new();
    for section in file
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
    {
        let data = section.data()?;
        if data.is_empty() {
            continue;
        }
        let (offset, _) = section.file_range().unwrap_or((0, 0));
        let normalized = normalize_x86(data, file.architecture());
        let symbol_fingerprint = fingerprint(section.name().ok(), normalized.as_ref(), data);
        let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        ranges.push((ir.symbols.len(), section.address(), size));
        ir.symbols.push(ArtifactSymbol {
            fingerprint: symbol_fingerprint,
            name: None,
            exported: false,
            section: u32::try_from(section.index().0).ok(),
            offset,
            size,
            size_inferred: true,
            code: data.to_vec(),
            normalized,
            body_fingerprint: None,
            inline_stack: Vec::new(),
            content_fingerprint: None,
            identity_by_order: false,
        });
    }
    Ok(ranges)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {

    use object::write::{Object as WriteObject, StandardSection, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope,
        write::SectionId,
    };
    use proptest::prelude::*;

    use super::{
        SymbolBoundary, boundaries_and_reads, collect_text_symbols, symbol_boundaries,
        symbol_fingerprint,
    };
    use crate::{ArtifactFormat, ArtifactIr, NormalizedInstructions};

    /// Ownership facts written the way a reader of the rule states them: scan
    /// every earlier owner for each symbol.
    fn boundaries_by_direct_scan(sorted: &[(u64, u64)], section_end: u64) -> Vec<SymbolBoundary> {
        let mut boundaries: Vec<SymbolBoundary> = Vec::new();
        for (position, (address, size)) in sorted.iter().enumerate() {
            let owner = (0..position).find(|prior| {
                boundaries[*prior].owner.is_none()
                    && sorted[*prior].0 <= *address
                    && *address < boundaries[*prior].end
            });
            let end = if owner.is_some() {
                *address
            } else if *size == 0 {
                sorted[position + 1..]
                    .iter()
                    .map(|(candidate, _)| *candidate)
                    .find(|candidate| candidate > address)
                    .unwrap_or(section_end)
            } else {
                address + size
            };
            boundaries.push(SymbolBoundary { owner, end });
        }
        boundaries
    }

    fn sorted_for_ownership(mut symbols: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
        symbols.sort_by_key(|(address, size)| (*address, std::cmp::Reverse(*size)));
        symbols
    }

    fn aliases(boundaries: &[SymbolBoundary]) -> Vec<bool> {
        boundaries
            .iter()
            .map(|entry| entry.owner.is_some())
            .collect()
    }

    fn text_symbol(name: String, section: SectionId, value: u64, size: u64) -> Symbol {
        Symbol {
            name: name.into_bytes(),
            value,
            size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        }
    }

    /// A Mach-O whose text section holds one two-byte function per symbol.
    ///
    /// Mach-O reports no symbol size, so every symbol takes the inferred
    /// boundary path.
    fn macho_fixture_with_text_symbols(count: usize) -> Vec<u8> {
        let mut object = WriteObject::new(
            BinaryFormat::MachO,
            Architecture::X86_64,
            Endianness::Little,
        );
        let text = object.section_id(StandardSection::Text);
        let offsets: Vec<_> = (0..count)
            .map(|_| object.append_section_data(text, &[0x90, 0xc3], 1))
            .collect();
        for (index, offset) in offsets.into_iter().enumerate() {
            object.add_symbol(text_symbol(format!("_body{index}"), text, offset, 0));
        }
        object.write().expect("write dense Mach-O fixture")
    }

    #[test]
    fn normalized_and_raw_payloads_with_the_same_bytes_have_distinct_identities() {
        let normalized = NormalizedInstructions {
            version: "x86-shape-v1".to_owned(),
            bytes: vec![1, 2, 3],
        };
        let normalized_fingerprint =
            symbol_fingerprint(Some("render"), Some(".text"), Some(&normalized), b"ignored");
        let raw_fingerprint = symbol_fingerprint(
            Some("render"),
            Some(".text"),
            None,
            b"x86-shape-v1\x01\x02\x03",
        );
        assert_ne!(normalized_fingerprint, raw_fingerprint);
    }

    #[test]
    fn field_boundaries_are_part_of_the_symbol_identity() {
        let left = symbol_fingerprint(Some("ab"), Some("c"), None, b"payload");
        let right = symbol_fingerprint(Some("a"), Some("bc"), None, b"payload");
        assert_ne!(left, right);
    }

    #[test]
    fn an_inferred_range_ends_at_the_next_strictly_greater_address() {
        let boundaries = symbol_boundaries(&[(10, 0), (10, 0), (14, 0)], 20);
        assert_eq!(
            boundaries,
            vec![
                SymbolBoundary {
                    owner: None,
                    end: 14
                },
                SymbolBoundary {
                    owner: Some(0),
                    end: 10
                },
                SymbolBoundary {
                    owner: None,
                    end: 20
                },
            ]
        );
    }

    #[test]
    fn only_a_shared_address_makes_a_zero_size_symbol_an_alias() {
        let boundaries = symbol_boundaries(&[(10, 4), (10, 0), (14, 0), (14, 0), (20, 8)], 28);
        assert_eq!(aliases(&boundaries), vec![false, true, false, true, false]);
        assert_eq!(
            boundaries.iter().map(|entry| entry.end).collect::<Vec<_>>(),
            vec![14, 10, 20, 14, 28]
        );
    }

    #[test]
    fn a_symbol_dense_text_section_is_analyzed_within_the_deadline() {
        let bytes = macho_fixture_with_text_symbols(100_000);
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut ir = ArtifactIr::empty(ArtifactFormat::MachO, &bytes);

        let index = collect_text_symbols(&file, &mut ir).unwrap();

        assert_eq!(index.ranges().len(), 100_000);
        assert_eq!(ir.symbols.len(), 100_000);
        assert!(
            ir.symbols
                .iter()
                .all(|symbol| symbol.size == 2 && symbol.size_inferred),
            "every inferred boundary ends at the next symbol"
        );
    }

    /// The boundaries are read out of the sorted list rather than rescanned
    /// against it, so the reads stay proportional to the symbol count however
    /// many symbols share an address.
    #[test]
    fn boundaries_are_read_proportionally_to_the_symbol_count() {
        for aliases_per_address in [1_usize, 8, 100_000] {
            let count = 100_000_usize;
            let sorted = (0..count)
                .map(|index| ((index / aliases_per_address) as u64, 0))
                .collect::<Vec<_>>();

            let (boundaries, reads) = boundaries_and_reads(&sorted, count as u64);

            assert_eq!(boundaries.len(), count);
            assert!(
                reads <= count.saturating_mul(4),
                "{aliases_per_address} aliases per address read {reads} entries \
                 for {count} symbols"
            );
        }
    }

    #[test]
    fn a_range_inside_bytes_another_symbol_owns_is_an_alias() {
        let sorted = sorted_for_ownership(vec![(10, 4), (10, 4), (10, 6), (12, 2), (20, 4)]);
        let boundaries = symbol_boundaries(&sorted, 24);
        assert_eq!(sorted[0], (10, 6), "the widest range at an address owns it");
        assert_eq!(aliases(&boundaries), vec![false, true, true, true, false]);
    }

    #[test]
    fn a_range_overlapping_the_end_of_an_owned_range_owns_no_bytes() {
        let boundaries = symbol_boundaries(&[(0, 8), (4, 8), (12, 0)], 16);
        assert_eq!(aliases(&boundaries), vec![false, true, false]);
        assert_eq!(boundaries[1].end, 4);
    }

    /// One text section whose every symbol declares a size reaching the
    /// section end, the shape that copied the section once per symbol.
    fn elf_fixture_with_symbols_sized_to_the_section_end(count: usize) -> Vec<u8> {
        let mut object =
            WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        let length = count as u64;
        object.append_section_data(text, &vec![0x90; count], 1);
        for index in 0..count {
            let start = index as u64;
            object.add_symbol(text_symbol(
                format!("overlap{index}"),
                text,
                start,
                length - start,
            ));
        }
        object.write().expect("write overlapping ELF fixture")
    }

    #[test]
    fn symbols_sized_to_the_section_end_copy_the_section_once() {
        let count = 100_000;
        let bytes = elf_fixture_with_symbols_sized_to_the_section_end(count);
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut ir = ArtifactIr::empty(ArtifactFormat::Elf, &bytes);

        let index = collect_text_symbols(&file, &mut ir).unwrap();

        assert_eq!(index.ranges().len(), count);
        let copied: usize = ir.symbols.iter().map(|symbol| symbol.code.len()).sum();
        assert_eq!(copied, count, "owned bytes never exceed the section");
        let owner = index.ranges()[0].position;
        assert_eq!(ir.symbols[owner].size, count as u64);
        assert!(
            index
                .ranges()
                .iter()
                .all(|range| index.symbol_owner(range.index) == Some(owner)),
            "every overlapping symbol resolves to the one owning the bytes"
        );
    }

    /// A 32-bit ARM ELF with one Thumb and one ARM-mode function of equal
    /// bytes. The Thumb symbol's value carries the mode in bit 0.
    fn arm_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
        let text = object.section_id(StandardSection::Text);
        let body = [0x00, 0xbf, 0x70, 0x47];
        let thumb = object.append_section_data(text, &body, 4);
        let arm = object.append_section_data(text, &body, 4);
        object.add_symbol(text_symbol("thumb".to_owned(), text, thumb | 1, 4));
        object.add_symbol(text_symbol("arm".to_owned(), text, arm, 4));
        object.write().expect("write ARM fixture")
    }

    #[test]
    fn a_thumb_symbol_is_sliced_from_its_first_instruction_byte() {
        let bytes = arm_fixture();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut ir = ArtifactIr::empty(ArtifactFormat::Elf, &bytes);

        let index = collect_text_symbols(&file, &mut ir).unwrap();

        let by_name = |name: &str| {
            ir.symbols
                .iter()
                .position(|symbol| symbol.name.as_deref() == Some(name))
                .unwrap()
        };
        let (thumb, arm) = (by_name("thumb"), by_name("arm"));
        assert_eq!(ir.symbols[thumb].code, vec![0x00, 0xbf, 0x70, 0x47]);
        assert_eq!(ir.symbols[thumb].code, ir.symbols[arm].code);
        assert_eq!(ir.symbols[arm].offset - ir.symbols[thumb].offset, 4);
        let thumb_range = index
            .ranges()
            .iter()
            .find(|range| range.position == thumb)
            .unwrap();
        assert_eq!(
            thumb_range.address % 2,
            0,
            "the join address drops the mode bit"
        );
        let report = crate::metrics::find_duplicates(&ir);
        assert_eq!(report.exact.len(), 1, "{report:#?}");
        assert_eq!(report.exact[0].members.len(), 2);
    }

    proptest! {
        #[test]
        fn one_pass_boundaries_agree_with_a_scan_of_every_earlier_owner(
            symbols in proptest::collection::vec((0_u64..16, 0_u64..6), 0..64)
        ) {
            let sorted = sorted_for_ownership(symbols);
            prop_assert_eq!(
                symbol_boundaries(&sorted, 24),
                boundaries_by_direct_scan(&sorted, 24)
            );
        }

        #[test]
        fn owned_ranges_never_overlap(
            symbols in proptest::collection::vec((0_u64..16, 0_u64..6), 0..64)
        ) {
            let sorted = sorted_for_ownership(symbols);
            let boundaries = symbol_boundaries(&sorted, 24);
            let mut owned: Vec<_> = sorted
                .iter()
                .zip(&boundaries)
                .filter(|(_, boundary)| boundary.owner.is_none())
                .map(|((address, _), boundary)| (*address, boundary.end))
                .collect();
            owned.sort_unstable();
            prop_assert!(owned.windows(2).all(|pair| pair[0].1 <= pair[1].0));
        }
    }
}
