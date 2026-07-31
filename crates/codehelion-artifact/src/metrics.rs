//! Format-neutral duplicate grouping over [`ArtifactIr`].
//!
//! Exact and normalized equality are equivalence relations, so their groups
//! are keyed directly by content rather than by a transitive similarity graph.
//! Near-match grouping is deliberately a later operation: it must use the
//! source engine's complete-linkage policy instead of union-find.

use std::collections::{BTreeMap, BTreeSet};

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

/// Size categories kept separate in artifact reports.
///
/// A `None` value means the current parser evidence cannot establish the
/// category. In particular, retained and shared-dependency sizes require a
/// resolved call graph, which not every format backend can provide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeClassification {
    /// Complete byte length observed directly from the input.
    pub observed_bytes: u64,
    /// Excess bytes in exact duplicate code groups.
    pub duplicated_bytes: u64,
    /// Bytes retained by call-graph reachability, when calculated.
    pub retained_bytes: Option<u64>,
    /// Bytes shared by several dependency closures, when calculated.
    pub shared_dependency_bytes: Option<u64>,
    /// Excess bytes in exact duplicate data groups.
    pub duplicated_data_bytes: u64,
    /// A theoretical maximum from directly observed exact duplication.
    ///
    /// This is explicitly not a claim that a linker or refactoring can remove
    /// the bytes without changing behaviour or layout.
    pub upper_bound_savings_bytes: Option<u64>,
    /// A source-informed refactoring estimate, unavailable before mapping.
    pub estimated_refactor_savings_bytes: Option<u64>,
    /// A before/after measured reduction, unavailable for one artifact.
    pub verified_savings_bytes: Option<u64>,
    /// Confidence in the duplicate observation. Exact byte equality is a
    /// direct observation, while normalized equality stays separate in the
    /// duplicate report.
    pub clone_confidence: EvidenceConfidence,
    /// Confidence in a possible size reduction. This is unavailable before
    /// source mapping and a measured refactoring supply actual evidence.
    pub savings_confidence: EvidenceConfidence,
    /// Conditions and omissions that qualify the derived categories.
    pub assumptions: Vec<String>,
}

/// Evidence strength reported without turning an observation into a promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceConfidence {
    /// Direct parser-observed facts establish the value.
    High,
    /// The result uses a conservative inference with known incompleteness.
    Medium,
    /// The result has substantial unresolved evidence.
    Low,
    /// The evidence necessary to calculate the value is absent.
    Unavailable,
}

/// Reachability result derived only from resolved local call edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadCodeReport {
    /// Symbols not reached from a parser-established export.
    pub symbols: Vec<ArtifactFingerprint>,
    /// Whether every relevant dispatch edge was resolved.
    pub definitive: bool,
    /// Why the result is conservative or unavailable.
    pub assumptions: Vec<String>,
}

/// The bytes exclusively retained by one reachable symbol's dominator region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedSize {
    /// The symbol whose removal makes the dominated region unreachable.
    pub symbol: ArtifactFingerprint,
    /// Sum of observed code sizes in its dominated region.
    pub retained_bytes: u64,
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
    let normalized = groups(&artifact.symbols, |symbol| {
        symbol.normalized.as_ref().map(|normalized| {
            // One byte separator is unambiguous because the version gets a
            // length prefix in `group_fingerprint` below.
            (normalized.version.as_str(), normalized.bytes.as_slice())
        })
    });
    DuplicateReport { exact, normalized }
}

/// Find exact duplicate data regions at or above `min_bytes`.
///
/// Data has no normalized representation: a match here means the byte stream
/// itself is equal. Short regions are deliberately excluded before grouping.
#[must_use]
pub fn find_duplicate_data(artifact: &ArtifactIr, min_bytes: u64) -> Vec<DuplicateGroup> {
    groups_data(&artifact.data_segments, min_bytes)
}

/// Derive the size categories supported by the currently observed IR.
#[must_use]
pub fn classify_sizes(artifact: &ArtifactIr) -> SizeClassification {
    let duplicates = find_duplicates(artifact);
    let duplicated_bytes = duplicates
        .exact
        .iter()
        .map(|group| group.duplicated_bytes)
        .sum();
    let duplicated_data_bytes = find_duplicate_data(artifact, DEFAULT_MIN_DUPLICATE_DATA_BYTES)
        .iter()
        .map(|group| group.duplicated_bytes)
        .sum();
    let mut assumptions = vec![
        "upper_bound_savings_bytes is not a guaranteed reduction".to_owned(),
        "estimated_refactor_savings_bytes needs source-artifact mapping".to_owned(),
    ];
    let graph_sizes = resolved_graph(artifact);
    if graph_sizes.is_none() {
        assumptions
            .push("retained and shared dependency sizes need a resolved call graph".to_owned());
    }
    let (retained_bytes, shared_dependency_bytes) = graph_sizes.map_or((None, None), |graph| {
        let retained_bytes = graph
            .reachable
            .iter()
            .map(|symbol| graph.sizes[symbol])
            .sum();
        let mut root_reach_counts: BTreeMap<ArtifactFingerprint, u64> = BTreeMap::new();
        for root in &graph.roots {
            for symbol in reachable_from(BTreeSet::from([*root]), artifact, &graph.sizes) {
                *root_reach_counts.entry(symbol).or_default() += 1;
            }
        }
        let shared_dependency_bytes = root_reach_counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(symbol, _)| graph.sizes[&symbol])
            .sum();
        (Some(retained_bytes), Some(shared_dependency_bytes))
    });
    SizeClassification {
        observed_bytes: artifact.observed_bytes,
        duplicated_bytes,
        retained_bytes,
        shared_dependency_bytes,
        duplicated_data_bytes,
        upper_bound_savings_bytes: Some(duplicated_bytes),
        estimated_refactor_savings_bytes: None,
        verified_savings_bytes: None,
        clone_confidence: EvidenceConfidence::High,
        savings_confidence: EvidenceConfidence::Unavailable,
        assumptions,
    }
}

/// Find symbols not reachable from parser-established exports.
///
/// An unresolved dispatch can target any local function, so it changes the
/// result from a definitive dead-code finding into a candidate list. No
/// exports means no trustworthy root set and therefore returns no finding.
#[must_use]
pub fn dead_code_candidates(artifact: &ArtifactIr) -> Option<DeadCodeReport> {
    if !artifact.capabilities.call_graph {
        return None;
    }
    let mut reachable: BTreeSet<ArtifactFingerprint> = artifact
        .symbols
        .iter()
        .filter(|symbol| symbol.exported)
        .map(|symbol| symbol.fingerprint)
        .collect();
    reachable.extend(artifact.entry_points.iter().copied());
    reachable.extend(artifact.indirect_references.iter().copied());
    if reachable.is_empty() {
        return None;
    }
    loop {
        let before = reachable.len();
        for call in &artifact.calls {
            if reachable.contains(&call.caller) {
                if let Some(target) = call.target {
                    reachable.insert(target);
                }
            }
        }
        if reachable.len() == before {
            break;
        }
    }
    let unresolved = artifact.calls.iter().any(|call| call.unresolved.is_some());
    let mut symbols: Vec<_> = artifact
        .symbols
        .iter()
        .map(|symbol| symbol.fingerprint)
        .filter(|fingerprint| !reachable.contains(fingerprint))
        .collect();
    symbols.sort();
    symbols.dedup();
    Some(DeadCodeReport {
        symbols,
        definitive: !unresolved,
        assumptions: if unresolved {
            vec!["unresolved dispatch prevents proving unreachable symbols are dead".to_owned()]
        } else {
            vec!["all recorded call edges were resolved locally".to_owned()]
        },
    })
}

/// Calculate retained code sizes from a complete, unambiguous local call graph.
///
/// The returned regions overlap (a dominator retains its descendants too), so
/// callers must never add them together as a total saving. Ambiguous duplicate
/// fingerprints and unresolved calls are refused rather than guessed.
#[must_use]
pub fn retained_sizes(artifact: &ArtifactIr) -> Option<Vec<RetainedSize>> {
    let graph = resolved_graph(artifact)?;
    let all = graph.reachable.clone();
    let mut dominators: BTreeMap<_, BTreeSet<_>> = graph
        .reachable
        .iter()
        .map(|node| {
            let initial = if graph.roots.contains(node) {
                BTreeSet::from([*node])
            } else {
                all.clone()
            };
            (*node, initial)
        })
        .collect();
    loop {
        let mut changed = false;
        for node in &graph.reachable {
            if graph.roots.contains(node) {
                continue;
            }
            let predecessors: Vec<_> = artifact
                .calls
                .iter()
                .filter_map(|call| {
                    (call.target == Some(*node) && graph.reachable.contains(&call.caller))
                        .then_some(call.caller)
                })
                .collect();
            if predecessors.is_empty() {
                continue;
            }
            let mut intersection = dominators[&predecessors[0]].clone();
            for predecessor in predecessors.iter().skip(1) {
                intersection.retain(|candidate| dominators[predecessor].contains(candidate));
            }
            intersection.insert(*node);
            if dominators[node] != intersection {
                dominators.insert(*node, intersection);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut result: Vec<_> = graph
        .reachable
        .iter()
        .map(|symbol| RetainedSize {
            symbol: *symbol,
            retained_bytes: graph
                .reachable
                .iter()
                .filter(|node| dominators[node].contains(symbol))
                .map(|node| graph.sizes[node])
                .sum(),
        })
        .collect();
    result.sort_by(|left, right| {
        right
            .retained_bytes
            .cmp(&left.retained_bytes)
            .then_with(|| left.symbol.cmp(&right.symbol))
    });
    Some(result)
}

/// Facts available only when every local graph edge and identity is sound.
struct ResolvedGraph {
    sizes: BTreeMap<ArtifactFingerprint, u64>,
    roots: BTreeSet<ArtifactFingerprint>,
    reachable: BTreeSet<ArtifactFingerprint>,
}

fn resolved_graph(artifact: &ArtifactIr) -> Option<ResolvedGraph> {
    if !artifact.capabilities.call_graph
        || artifact.calls.iter().any(|call| call.unresolved.is_some())
    {
        return None;
    }
    let mut sizes = BTreeMap::new();
    for symbol in &artifact.symbols {
        if sizes.insert(symbol.fingerprint, symbol.size).is_some() {
            return None;
        }
    }
    let roots: BTreeSet<_> = artifact
        .symbols
        .iter()
        .filter(|symbol| symbol.exported)
        .map(|symbol| symbol.fingerprint)
        .chain(artifact.entry_points.iter().copied())
        .chain(artifact.indirect_references.iter().copied())
        .collect();
    if roots.is_empty() || !roots.iter().all(|root| sizes.contains_key(root)) {
        return None;
    }
    if artifact.calls.iter().any(|call| {
        !sizes.contains_key(&call.caller)
            || !call
                .target
                .is_some_and(|target| sizes.contains_key(&target))
    }) {
        return None;
    }
    let reachable = reachable_from(roots.clone(), artifact, &sizes);
    Some(ResolvedGraph {
        sizes,
        roots,
        reachable,
    })
}

fn reachable_from(
    mut reachable: BTreeSet<ArtifactFingerprint>,
    artifact: &ArtifactIr,
    sizes: &BTreeMap<ArtifactFingerprint, u64>,
) -> BTreeSet<ArtifactFingerprint> {
    loop {
        let before = reachable.len();
        for call in &artifact.calls {
            if reachable.contains(&call.caller) {
                if let Some(target) = call.target.filter(|target| sizes.contains_key(target)) {
                    reachable.insert(target);
                }
            }
        }
        if reachable.len() == before {
            return reachable;
        }
    }
}

fn groups<'a>(
    symbols: &'a [ArtifactSymbol],
    key: impl Fn(&'a ArtifactSymbol) -> Option<(&'a str, &'a [u8])>,
) -> Vec<DuplicateGroup> {
    let mut buckets: BTreeMap<(String, Vec<u8>), Vec<&ArtifactSymbol>> = BTreeMap::new();
    for symbol in symbols {
        let Some((version, content)) = key(symbol) else {
            continue;
        };
        buckets
            .entry((version.to_owned(), content.to_vec()))
            .or_default()
            .push(symbol);
    }
    let mut result: Vec<DuplicateGroup> = buckets
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|((version, content), members)| group(&version, &content, members))
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
    let mut buckets: BTreeMap<Vec<u8>, Vec<&ArtifactDataSegment>> = BTreeMap::new();
    for segment in segments {
        if segment.bytes.len() as u64 >= min_bytes {
            buckets
                .entry(segment.bytes.clone())
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
                fingerprint: group_fingerprint("data-exact", &bytes),
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
    use crate::{ArtifactDataSegment, ArtifactFormat, NormalizedInstructions};
    use proptest::prelude::*;

    fn symbol(offset: u64, code: &[u8], normalized: Option<&[u8]>) -> ArtifactSymbol {
        ArtifactSymbol {
            fingerprint: ArtifactFingerprint::from_content("test-symbol", &offset.to_le_bytes()),
            name: None,
            exported: false,
            section: Some(1),
            offset,
            size: code.len() as u64,
            size_inferred: false,
            code: code.to_vec(),
            normalized: normalized.map(|bytes| NormalizedInstructions {
                version: "test-normal-v1".to_owned(),
                bytes: bytes.to_vec(),
            }),
            inline_stack: Vec::new(),
        }
    }

    #[test]
    fn exact_and_normalized_groups_are_reported_separately_and_deterministically() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
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

    #[test]
    fn size_categories_separate_observed_data_and_unavailable_estimates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input bytes");
        artifact.symbols = vec![symbol(10, &[1, 2, 3], None), symbol(20, &[1, 2, 3], None)];
        let bytes = vec![7; 16];
        artifact.data_segments = vec![
            ArtifactDataSegment {
                fingerprint: ArtifactFingerprint::from_content("data", b"one"),
                section: None,
                offset: 100,
                bytes: bytes.clone(),
            },
            ArtifactDataSegment {
                fingerprint: ArtifactFingerprint::from_content("data", b"two"),
                section: None,
                offset: 200,
                bytes,
            },
        ];
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.observed_bytes, 11);
        assert_eq!(sizes.duplicated_bytes, 3);
        assert_eq!(sizes.duplicated_data_bytes, 16);
        assert_eq!(sizes.upper_bound_savings_bytes, Some(3));
        assert!(sizes.estimated_refactor_savings_bytes.is_none());
        assert!(sizes.verified_savings_bytes.is_none());
        assert_eq!(sizes.clone_confidence, EvidenceConfidence::High);
        assert_eq!(sizes.savings_confidence, EvidenceConfidence::Unavailable);
        assert!(sizes.duplicated_bytes >= sizes.upper_bound_savings_bytes.unwrap_or(u64::MAX));
    }

    proptest! {
        #[test]
        fn size_categories_keep_exact_duplicate_bounds_for_disjoint_regions(
            lengths in prop::collection::vec(16_usize..128, 0..24),
        ) {
            let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"");
            let mut offset = 0_u64;
            for (index, length) in lengths.iter().copied().enumerate() {
                let bytes = vec![u8::try_from(index).unwrap_or(u8::MAX); length];
                artifact.symbols.push(symbol(offset, &bytes, None));
                offset += length as u64;
                artifact.symbols.push(symbol(offset, &bytes, None));
                offset += length as u64;
                artifact.data_segments.push(ArtifactDataSegment {
                    fingerprint: ArtifactFingerprint::from_content("property-data", &bytes),
                    section: Some(11),
                    offset,
                    bytes: bytes.clone(),
                });
                offset += length as u64;
                artifact.data_segments.push(ArtifactDataSegment {
                    fingerprint: ArtifactFingerprint::from_content("property-data", &bytes),
                    section: Some(11),
                    offset,
                    bytes,
                });
                offset += length as u64;
            }
            artifact.observed_bytes = offset;
            let sizes = classify_sizes(&artifact);
            prop_assert!(sizes.duplicated_bytes <= sizes.observed_bytes);
            prop_assert!(sizes.duplicated_data_bytes <= sizes.observed_bytes);
            prop_assert_eq!(
                sizes.upper_bound_savings_bytes,
                Some(sizes.duplicated_bytes)
            );
            prop_assert!(
                sizes.estimated_refactor_savings_bytes.is_none()
                    && sizes.verified_savings_bytes.is_none()
            );
        }
    }

    #[test]
    fn unresolved_dispatch_downgrades_unreachable_symbols_to_candidates() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let live = symbol(2, &[2], None);
        let dead = symbol(3, &[3], None);
        artifact.symbols = vec![entry.clone(), live.clone(), dead.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![crate::ArtifactCall {
            caller: entry.fingerprint,
            target: Some(live.fingerprint),
            unresolved: None,
        }];
        let report = dead_code_candidates(&artifact).unwrap();
        assert!(report.definitive);
        assert_eq!(report.symbols, vec![dead.fingerprint]);
        artifact.calls.push(crate::ArtifactCall {
            caller: live.fingerprint,
            target: None,
            unresolved: Some(crate::UnresolvedCall::IndirectTable),
        });
        assert!(!dead_code_candidates(&artifact).unwrap().definitive);
    }

    #[test]
    fn retained_size_uses_dominator_regions_without_summing_their_overlap() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let middle = symbol(2, &[2, 2], None);
        let leaf = symbol(3, &[3, 3, 3], None);
        artifact.symbols = vec![entry.clone(), middle.clone(), leaf.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![
            crate::ArtifactCall {
                caller: entry.fingerprint,
                target: Some(middle.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: middle.fingerprint,
                target: Some(leaf.fingerprint),
                unresolved: None,
            },
        ];
        let retained = retained_sizes(&artifact).unwrap();
        let value = |fingerprint| {
            retained
                .iter()
                .find(|item| item.symbol == fingerprint)
                .unwrap()
                .retained_bytes
        };
        assert_eq!(value(entry.fingerprint), 6);
        assert_eq!(value(middle.fingerprint), 5);
        assert_eq!(value(leaf.fingerprint), 3);
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.retained_bytes, Some(6));
        assert_eq!(sizes.shared_dependency_bytes, Some(0));
        artifact.calls[1].unresolved = Some(crate::UnresolvedCall::IndirectTable);
        assert!(retained_sizes(&artifact).is_none());
    }

    #[test]
    fn retained_size_converges_for_a_cycle() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let entry = symbol(1, &[1], None);
        let left = symbol(2, &[2, 2], None);
        let right = symbol(3, &[3, 3, 3], None);
        artifact.symbols = vec![entry.clone(), left.clone(), right.clone()];
        artifact.symbols[0].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![
            crate::ArtifactCall {
                caller: entry.fingerprint,
                target: Some(left.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: left.fingerprint,
                target: Some(right.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: right.fingerprint,
                target: Some(left.fingerprint),
                unresolved: None,
            },
        ];
        let retained = retained_sizes(&artifact).unwrap();
        let value = |fingerprint| {
            retained
                .iter()
                .find(|item| item.symbol == fingerprint)
                .unwrap()
                .retained_bytes
        };
        assert_eq!(value(entry.fingerprint), 6);
        assert_eq!(value(left.fingerprint), 5);
        assert_eq!(value(right.fingerprint), 3);
    }

    #[test]
    fn size_categories_keep_shared_dependencies_separate() {
        let mut artifact = ArtifactIr::empty(ArtifactFormat::Wasm, b"input");
        let left_root = symbol(1, &[1], None);
        let right_root = symbol(2, &[2, 2], None);
        let shared = symbol(3, &[3, 3, 3], None);
        artifact.symbols = vec![left_root.clone(), right_root.clone(), shared.clone()];
        artifact.symbols[0].exported = true;
        artifact.symbols[1].exported = true;
        artifact.capabilities.call_graph = true;
        artifact.calls = vec![
            crate::ArtifactCall {
                caller: left_root.fingerprint,
                target: Some(shared.fingerprint),
                unresolved: None,
            },
            crate::ArtifactCall {
                caller: right_root.fingerprint,
                target: Some(shared.fingerprint),
                unresolved: None,
            },
        ];
        let sizes = classify_sizes(&artifact);
        assert_eq!(sizes.retained_bytes, Some(6));
        assert_eq!(sizes.shared_dependency_bytes, Some(3));
    }
}
