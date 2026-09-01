//! Shared native-object collection helpers.

use std::collections::{BTreeMap, HashMap};

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

/// Copy the section, read-only data, and relocation facts common to native
/// object formats into format-neutral IR.
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

/// Determine a native symbol's byte extent without attributing bytes to a
/// zero-size alias.
///
/// A declared size always wins. For a boundary inferred from neighbouring
/// symbols, only the next strictly greater address delimits the range. If an
/// explicit definition shares the address, or an earlier zero-size symbol has
/// already claimed that inferred range, this symbol is an alias and remains
/// explicitly zero-sized.
#[must_use]
pub fn symbol_size(
    address: u64,
    declared_size: u64,
    is_zero_size_alias: bool,
    following_addresses: impl IntoIterator<Item = u64>,
    section_end: u64,
) -> u64 {
    if declared_size != 0 {
        return declared_size;
    }
    if is_zero_size_alias {
        return 0;
    }
    following_addresses
        .into_iter()
        .find(|candidate| *candidate > address)
        .unwrap_or(section_end)
        .saturating_sub(address)
}

/// Remove only conventional trailing padding from an inferred native symbol.
///
/// Explicit symbol sizes are authoritative and must not use this helper.
#[must_use]
pub fn trim_inferred_symbol_padding(code: &[u8], architecture: object::Architecture) -> &[u8] {
    crate::x86::trim_inferred_padding(code, architecture)
}

/// Alias and boundary facts for one entry of an address-sorted symbol list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SymbolBoundary {
    /// Whether an equal-address definition makes this symbol an alias.
    alias: bool,
    /// First address in the list that is strictly greater, when one exists.
    next_greater_address: Option<u64>,
}

/// Derive alias and boundary facts for an address-sorted symbol list in one
/// pass over it.
///
/// Sorting puts symbols sharing an address in one contiguous run, so both facts
/// are run-local: a zero-size symbol is an alias when its run holds an earlier
/// member or any sized member, and the only address that can delimit an
/// inferred range is the next run's. Answering either question per symbol would
/// rescan the whole section instead, which a format reporting every symbol as
/// zero-sized turns into a scan of the section per symbol.
fn symbol_boundaries(sorted: &[(u64, u64)]) -> Vec<SymbolBoundary> {
    boundaries_and_reads(sorted).0
}

/// [`symbol_boundaries`] beside the number of entries it read.
///
/// The count is what separates this from the whole-list rescan it replaced: a
/// reader that consults every earlier symbol is quadratic in the number of
/// symbols sharing a section, which a wall clock only reveals on a machine
/// that happens to be idle. Callers outside the tests take the boundaries and
/// drop the count.
fn boundaries_and_reads(sorted: &[(u64, u64)]) -> (Vec<SymbolBoundary>, usize) {
    let mut boundaries = Vec::with_capacity(sorted.len());
    let mut reads = 0_usize;
    let mut start = 0;
    while let Some(&(address, _)) = sorted.get(start) {
        let run = sorted.get(start..).unwrap_or_default();
        let end = start.saturating_add(run.partition_point(|(candidate, _)| *candidate == address));
        let run = sorted.get(start..end).unwrap_or_default();
        let has_sized_member = run.iter().any(|(_, size)| *size != 0);
        let next_greater_address = sorted.get(end).map(|(address, _)| *address);
        boundaries.extend(
            run.iter()
                .enumerate()
                .map(|(offset, (_, size))| SymbolBoundary {
                    alias: *size == 0 && (offset > 0 || has_sized_member),
                    next_greater_address,
                }),
        );
        // Each run is read once to find its extent, once for a sized member
        // and once to emit, plus the binary search that located its end.
        reads = reads
            .saturating_add(run.len().saturating_mul(3))
            .saturating_add(run.len().max(1).ilog2() as usize);
        start = end;
    }
    (boundaries, reads)
}

/// Transient native-symbol data used only by format-specific join code.
#[derive(Debug, Clone, Copy)]
pub struct NativeSymbolRange {
    /// Stable identity assigned to the symbol.
    pub fingerprint: ArtifactFingerprint,
    /// Parser-local symbol index.
    pub index: object::SymbolIndex,
    /// Parser-local section index used to disambiguate relocatable addresses.
    pub section: object::SectionIndex,
    /// Parser address used only for local joins.
    pub address: u64,
    /// Retained code length.
    pub size: u64,
}

/// Collect text symbols using the shared native identity and boundary rules.
///
/// # Errors
///
/// Returns an error when a text section cannot be read.
pub fn collect_text_symbols(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
) -> Result<Vec<NativeSymbolRange>, object::Error> {
    let mut ranges = Vec::new();
    for section in file
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
    {
        let section_index = section.index();
        let data = section.data()?;
        let (section_offset, _) = section.file_range().unwrap_or((0, 0));
        let mut symbols: Vec<_> = file
            .symbols()
            .filter(|symbol| {
                symbol.section_index() == Some(section_index)
                    && symbol.kind() == SymbolKind::Text
                    && !symbol.is_undefined()
            })
            .collect();
        symbols.sort_by_key(ObjectSymbol::address);
        let boundaries = symbol_boundaries(
            &symbols
                .iter()
                .map(|symbol| (symbol.address(), symbol.size()))
                .collect::<Vec<_>>(),
        );
        for (symbol, boundary) in symbols.iter().zip(boundaries) {
            let Some(relative) = symbol.address().checked_sub(section.address()) else {
                continue;
            };
            let size = symbol_size(
                symbol.address(),
                symbol.size(),
                boundary.alias,
                boundary.next_greater_address,
                section
                    .address()
                    .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX)),
            );
            let (Ok(start), Ok(size)) = (usize::try_from(relative), usize::try_from(size)) else {
                continue;
            };
            let Some(raw) = data.get(start..start.saturating_add(size)) else {
                continue;
            };
            let code = if symbol.size() == 0 {
                trim_inferred_symbol_padding(raw, file.architecture())
            } else {
                raw
            };
            if code.is_empty() && symbol.size() != 0 {
                continue;
            }
            let raw_name = symbol.name().ok().filter(|name| !name.is_empty());
            let name = raw_name.map(demangle);
            let fingerprint_name = raw_name.map(|name| {
                let canonical = if file.format() == object::BinaryFormat::MachO {
                    name.strip_prefix('_').unwrap_or(name)
                } else {
                    name
                };
                demangle(canonical)
            });
            let normalized = normalize_x86(code, file.architecture());
            let fingerprint = symbol_fingerprint(
                fingerprint_name.as_deref(),
                Some("text"),
                normalized.as_ref(),
                code,
            );
            let size = u64::try_from(code.len()).unwrap_or(u64::MAX);
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
            });
            ranges.push(NativeSymbolRange {
                fingerprint,
                index: symbol.index(),
                section: section_index,
                address: symbol.address(),
                size,
            });
        }
    }
    Ok(ranges)
}

/// Every code record of a native object with the address that joins it to
/// debug information.
#[derive(Debug, Default)]
pub struct NativeTextSymbols {
    /// Symbol-table entries, empty for an object without code symbols.
    pub symbols: Vec<NativeSymbolRange>,
    /// Join address and retained length of each appended code record, whether
    /// it came from the symbol table or from an inferred region.
    pub addresses: HashMap<ArtifactFingerprint, (u64, u64)>,
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
    let symbols = collect_text_symbols(file, ir)?;
    let mut addresses: HashMap<_, _> = symbols
        .iter()
        .map(|range| (range.fingerprint, (range.address, range.size)))
        .collect();
    if ir.symbols.is_empty() {
        addresses.extend(
            infer_text_regions(file, ir, |section, normalized, data| {
                symbol_fingerprint(None, section, normalized, data)
            })?
            .into_iter()
            .map(|(fingerprint, address, size)| (fingerprint, (address, size))),
        );
    }
    Ok(NativeTextSymbols { symbols, addresses })
}

fn append_field(identity: &mut Vec<u8>, value: &[u8]) {
    identity.extend(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    identity.extend(value);
}

fn relocation_target_name(
    file: &object::File<'_>,
    target: object::RelocationTarget,
) -> Option<String> {
    let object::RelocationTarget::Symbol(index) = target else {
        return None;
    };
    file.symbol_by_index(index)
        .ok()
        .and_then(|symbol| symbol.name().ok())
        .filter(|name| !name.is_empty())
        .map(demangle)
}

/// Add one explicitly inferred region for every non-empty text section.
///
/// The caller supplies its format-domain fingerprint recipe. Address ranges
/// are returned as transient join evidence for backends that can attach debug
/// frames; they are never used as identities.
///
/// # Errors
///
/// Returns an object-reader error when an executable section cannot be read.
pub fn infer_text_regions<F>(
    file: &object::File<'_>,
    ir: &mut ArtifactIr,
    mut fingerprint: F,
) -> Result<Vec<(ArtifactFingerprint, u64, u64)>, object::Error>
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
        });
        ranges.push((symbol_fingerprint, section.address(), size));
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
        symbol_fingerprint, symbol_size,
    };
    use crate::{ArtifactFormat, ArtifactIr, NormalizedInstructions};

    /// Alias and boundary facts written the way a reader of the rule states
    /// them: scan the whole symbol list for every symbol.
    fn boundaries_by_direct_scan(sorted: &[(u64, u64)]) -> Vec<SymbolBoundary> {
        sorted
            .iter()
            .enumerate()
            .map(|(position, (address, size))| SymbolBoundary {
                alias: *size == 0
                    && (sorted[..position].iter().any(|(prior, _)| prior == address)
                        || sorted
                            .iter()
                            .any(|(other, other_size)| other == address && *other_size != 0)),
                next_greater_address: sorted[position.saturating_add(1)..]
                    .iter()
                    .map(|(candidate, _)| *candidate)
                    .find(|candidate| *candidate > *address),
            })
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
    fn inferred_symbol_size_uses_the_next_strictly_greater_address() {
        assert_eq!(symbol_size(10, 0, false, [10, 10, 14], 20), 4);
    }

    #[test]
    fn zero_size_alias_remains_an_explicit_empty_region() {
        assert_eq!(symbol_size(10, 0, true, [14], 20), 0);
    }

    #[test]
    fn only_a_shared_address_makes_a_zero_size_symbol_an_alias() {
        let boundaries = symbol_boundaries(&[(10, 4), (10, 0), (14, 0), (14, 0), (20, 8)]);
        assert_eq!(
            boundaries
                .iter()
                .map(|entry| entry.alias)
                .collect::<Vec<_>>(),
            vec![false, true, false, true, false]
        );
        assert_eq!(
            boundaries
                .iter()
                .map(|entry| entry.next_greater_address)
                .collect::<Vec<_>>(),
            vec![Some(14), Some(14), Some(20), Some(20), None]
        );
    }

    #[test]
    fn a_symbol_dense_text_section_is_analyzed_within_the_deadline() {
        let bytes = macho_fixture_with_text_symbols(100_000);
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let mut ir = ArtifactIr::empty(ArtifactFormat::MachO, &bytes);

        let ranges = collect_text_symbols(&file, &mut ir).unwrap();

        assert_eq!(ranges.len(), 100_000);
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

            let (boundaries, reads) = boundaries_and_reads(&sorted);

            assert_eq!(boundaries.len(), count);
            assert!(
                reads <= count.saturating_mul(4),
                "{aliases_per_address} aliases per address read {reads} entries \
                 for {count} symbols"
            );
        }
    }

    proptest! {
        #[test]
        fn run_local_boundaries_agree_with_a_scan_of_the_whole_symbol_list(
            symbols in proptest::collection::vec((0_u64..16, 0_u64..3), 0..64)
        ) {
            let mut sorted = symbols;
            sorted.sort_by_key(|(address, _)| *address);
            prop_assert_eq!(symbol_boundaries(&sorted), boundaries_by_direct_scan(&sorted));
        }
    }
}
