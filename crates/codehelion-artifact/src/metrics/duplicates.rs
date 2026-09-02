//! Equality classes over one artifact's code symbols and data segments.
//!
//! Exact and normalized equality are equivalence relations, so their groups are
//! keyed directly by content rather than by a transitive similarity graph.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ArtifactDataSegment, ArtifactFingerprint, ArtifactIr, ArtifactSymbol};

/// The smallest data region that duplicate-data analysis reports by default.
///
/// Tiny constants occur frequently and are not useful bloat signals. Callers
/// may use [`find_duplicate_data`] with another threshold when they have a
/// format- or project-specific reason to do so.
pub const DEFAULT_MIN_DUPLICATE_DATA_BYTES: u64 = 16;

/// Duplicate groups found in one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateReport {
    /// Groups whose machine code bytes are identical.
    pub exact: Vec<DuplicateGroup>,
    /// Groups whose version-compatible normalized instructions are identical.
    pub normalized: Vec<DuplicateGroup>,
}

/// One equality class of duplicate artifact symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateGroup {
    /// Stable content identity for this group.
    pub fingerprint: ArtifactFingerprint,
    /// The byte size that could be removed if every member except the largest
    /// canonical member were safely merged. It is an observed duplicate count,
    /// not a claimed binary-size saving.
    pub duplicated_bytes: u64,
    /// Each observed occurrence. Offset distinguishes occurrences within this
    /// one artifact but never participates in the stable fingerprint.
    pub members: Vec<DuplicateMember>,
}

/// One occurrence in a [`DuplicateGroup`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateMember {
    /// Stable content fingerprint of the symbol.
    pub symbol: ArtifactFingerprint,
    /// Artifact offset for this occurrence.
    pub offset: u64,
    /// Observed symbol size in bytes.
    pub size: u64,
}

/// Find exact and normalized duplicate groups in `artifact`.
#[must_use]
pub fn find_duplicates(artifact: &ArtifactIr) -> DuplicateReport {
    let exact = groups(&artifact.symbols, |symbol| {
        Some(("exact", symbol.code.as_slice()))
    });
    let normalized = if artifact.capabilities.normalized_duplicates {
        groups(&artifact.symbols, |symbol| {
            symbol.normalized.as_ref().map(|normalized| {
                // One byte separator is unambiguous because the version gets a
                // length prefix in `group_fingerprint` below.
                (normalized.version.as_str(), normalized.bytes.as_slice())
            })
        })
    } else {
        Vec::new()
    };
    DuplicateReport { exact, normalized }
}

/// Find exact duplicate data regions at or above `min_bytes`.
///
/// Data has no normalized representation: a match here means the byte stream
/// itself is equal. Short regions are deliberately excluded before grouping.
#[must_use]
pub fn find_duplicate_data(artifact: &ArtifactIr, min_bytes: u64) -> Vec<DuplicateGroup> {
    if !artifact.capabilities.independent_data_segments {
        return Vec::new();
    }
    groups_data(&artifact.data_segments, min_bytes)
}

fn groups<'a>(
    symbols: &'a [ArtifactSymbol],
    key: impl Fn(&'a ArtifactSymbol) -> Option<(&'a str, &'a [u8])>,
) -> Vec<DuplicateGroup> {
    let mut buckets: BTreeMap<(&str, &[u8]), Vec<&ArtifactSymbol>> = BTreeMap::new();
    for symbol in symbols {
        let Some((version, content)) = key(symbol) else {
            continue;
        };
        buckets.entry((version, content)).or_default().push(symbol);
    }
    let mut result: Vec<DuplicateGroup> = buckets
        .into_iter()
        // Symbols with no observed content share the empty key without sharing
        // anything: bucketing them would count aliases as a duplicate group
        // whose removable size is zero.
        .filter(|((_, content), members)| members.len() > 1 && !content.is_empty())
        .map(|((version, content), members)| group(version, content, members))
        .collect();
    result.sort_by(|left, right| {
        right
            .duplicated_bytes
            .cmp(&left.duplicated_bytes)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

fn group(version: &str, content: &[u8], symbols: Vec<&ArtifactSymbol>) -> DuplicateGroup {
    let mut members: Vec<DuplicateMember> = symbols
        .into_iter()
        .map(|symbol| DuplicateMember {
            symbol: symbol.fingerprint,
            offset: symbol.offset,
            size: symbol.size,
        })
        .collect();
    members.sort_by_key(|member| (member.offset, member.symbol));
    let total = members.iter().map(|member| member.size).sum::<u64>();
    let canonical = members.iter().map(|member| member.size).max().unwrap_or(0);
    DuplicateGroup {
        fingerprint: group_fingerprint(version, content),
        duplicated_bytes: total.saturating_sub(canonical),
        members,
    }
}

fn groups_data(segments: &[ArtifactDataSegment], min_bytes: u64) -> Vec<DuplicateGroup> {
    let mut buckets: BTreeMap<&[u8], Vec<&ArtifactDataSegment>> = BTreeMap::new();
    for segment in segments {
        if segment.bytes.len() as u64 >= min_bytes {
            buckets
                .entry(segment.bytes.as_slice())
                .or_default()
                .push(segment);
        }
    }
    let mut result: Vec<DuplicateGroup> = buckets
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|(bytes, segments)| {
            let mut members: Vec<DuplicateMember> = segments
                .into_iter()
                .map(|segment| DuplicateMember {
                    symbol: segment.fingerprint,
                    offset: segment.offset,
                    size: segment.bytes.len() as u64,
                })
                .collect();
            members.sort_by_key(|member| (member.offset, member.symbol));
            let total = members.iter().map(|member| member.size).sum::<u64>();
            let canonical = members.iter().map(|member| member.size).max().unwrap_or(0);
            DuplicateGroup {
                fingerprint: group_fingerprint("data-exact", bytes),
                duplicated_bytes: total.saturating_sub(canonical),
                members,
            }
        })
        .collect();
    result.sort_by(|left, right| {
        right
            .duplicated_bytes
            .cmp(&left.duplicated_bytes)
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

fn group_fingerprint(version: &str, content: &[u8]) -> ArtifactFingerprint {
    let mut identity = Vec::new();
    identity.extend((version.len() as u64).to_le_bytes());
    identity.extend(version.as_bytes());
    identity.extend(content);
    ArtifactFingerprint::from_content("artifact-duplicate-group", &identity)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ArtifactFormat;
    use crate::metrics::classify_sizes;
    use crate::metrics::tests::symbol;

    #[test]
    fn exact_and_normalized_groups_are_reported_separately_and_deterministically() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.capabilities.normalized_duplicates = true;
        artifact.symbols = vec![
            symbol(30, &[1, 2], Some(&[9])),
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[1, 3], Some(&[9])),
            symbol(40, &[5], None),
        ];
        let duplicates = find_duplicates(&artifact);
        assert_eq!(duplicates.exact.len(), 1);
        assert_eq!(duplicates.exact[0].members.len(), 2);
        assert_eq!(duplicates.exact[0].duplicated_bytes, 2);
        assert_eq!(
            duplicates.exact[0]
                .members
                .iter()
                .map(|member| member.offset)
                .collect::<Vec<_>>(),
            vec![10, 30]
        );
        assert_eq!(duplicates.normalized.len(), 1);
        assert_eq!(duplicates.normalized[0].members.len(), 3);
        assert_eq!(duplicates.normalized[0].duplicated_bytes, 4);
        assert_eq!(find_duplicates(&artifact), duplicates);
    }

    /// Symbols with no observed content are aliases of nothing in particular,
    /// so they may not form a group of their own: a group whose members share
    /// zero bytes offers no removable size, and letting the alias count vary
    /// the group count makes every comparison report a difference of zero.
    #[test]
    fn symbols_sharing_no_observed_content_form_no_duplicate_group() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        artifact.capabilities.normalized_duplicates = true;
        artifact.symbols = vec![
            symbol(10, &[], Some(&[])),
            symbol(20, &[], Some(&[])),
            symbol(30, &[], Some(&[])),
        ];

        let duplicates = find_duplicates(&artifact);

        assert!(duplicates.exact.is_empty());
        assert!(duplicates.normalized.is_empty());
        assert_eq!(classify_sizes(&artifact).duplicated_bytes, 0);

        artifact.symbols.push(symbol(40, &[1, 2], Some(&[9])));
        artifact.symbols.push(symbol(50, &[1, 2], Some(&[9])));
        let with_content = find_duplicates(&artifact);

        assert_eq!(with_content.exact.len(), 1);
        assert_eq!(with_content.exact[0].members.len(), 2);
        assert_eq!(with_content.exact[0].duplicated_bytes, 2);
        assert_eq!(with_content.normalized.len(), 1);
        assert_eq!(with_content.normalized[0].members.len(), 2);

        // The same artifact without the aliases answers identically, which is
        // what keeps two builds differing only in how many zero-size aliases
        // they carry from comparing as a change.
        let mut sized_only = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        sized_only.capabilities.normalized_duplicates = true;
        sized_only.symbols = vec![
            symbol(40, &[1, 2], Some(&[9])),
            symbol(50, &[1, 2], Some(&[9])),
        ];
        assert_eq!(find_duplicates(&sized_only), with_content);
        assert_eq!(classify_sizes(&sized_only), classify_sizes(&artifact));
    }

    #[test]
    fn normalized_groups_are_unavailable_without_a_supported_normalizer() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Elf, b"input");
        artifact.symbols = vec![
            symbol(10, &[1, 2], Some(&[9])),
            symbol(20, &[3, 4], Some(&[9])),
        ];

        let duplicates = find_duplicates(&artifact);

        assert!(duplicates.exact.is_empty());
        assert!(duplicates.normalized.is_empty());
    }
}
