//! Shared native-object collection helpers.

use std::collections::BTreeMap;

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
        for (position, symbol) in symbols.iter().enumerate() {
            let Some(relative) = symbol.address().checked_sub(section.address()) else {
                continue;
            };
            let alias = symbol.size() == 0
                && (symbols[..position]
                    .iter()
                    .any(|prior| prior.address() == symbol.address())
                    || symbols
                        .iter()
                        .any(|other| other.address() == symbol.address() && other.size() != 0));
            let size = symbol_size(
                symbol.address(),
                symbol.size(),
                alias,
                symbols[position.saturating_add(1)..]
                    .iter()
                    .map(ObjectSymbol::address),
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
            inline_stack: Vec::new(),
        });
        ranges.push((symbol_fingerprint, section.address(), size));
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::{symbol_fingerprint, symbol_size};
    use crate::NormalizedInstructions;

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
}
