//! Fallback correlation passes and unambiguous byte attribution.

use super::name::{
    canonical_symbol_name, normalized_clang_template_display_name,
    normalized_clang_template_owner_name, normalized_generic_instantiation_key,
    uniformly_separated,
};
use super::predicate::paths_match;
use super::{InstantiationIndex, ResolvedSymbolIndex, SourceLocationIndex};
use crate::artifact::correlation::mapping::{
    BuildVariantFingerprint, source_unit_instance_fingerprint,
};
use crate::artifact::correlation::source_kind_order;
use crate::artifact::{
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactIr, BTreeMap, BTreeSet, FilePath,
    MappingEvidence, MappingEvidenceFact, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
    SourceFragmentIdentity, SourceResolvedCall,
};

/// Attribute a symbol's observed bytes only when one exact fragment mapping
/// accounts for it. Units can contain fragments, so unit mappings neither
/// create nor block this fragment-level split.
pub(in crate::artifact) fn assign_unambiguous_fragment_bytes(
    artifact: &ArtifactIr,
    scan_root: &FilePath,
    fragments: &[SourceFragmentIdentity],
    mappings: &mut [ArtifactAnalysisMapping],
) {
    let fragments: BTreeMap<_, _> = fragments
        .iter()
        .map(|fragment| (*fragment.finding_id.as_bytes(), fragment))
        .collect();
    let mut fragment_mappings: BTreeMap<[u8; 16], Vec<usize>> = BTreeMap::new();
    for (index, mapping) in mappings.iter().enumerate() {
        if mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
            && mapping.evidence.confidence()
                == Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Exact)
        {
            fragment_mappings
                .entry(mapping.artifact_symbol_fingerprint)
                .or_default()
                .push(index);
        }
    }
    for symbol in &artifact.symbols {
        let Some(indices) = fragment_mappings.get(&symbol.fingerprint.as_bytes()) else {
            continue;
        };
        if let [index] = indices.as_slice() {
            let mapping = &mut mappings[*index];
            let Some(fragment) = fragments.get(&mapping.source_instance_fingerprint) else {
                continue;
            };
            let Some((covered_lines, symbol_lines, whole_symbol)) =
                symbol_line_coverage(symbol, scan_root, fragment)
            else {
                continue;
            };
            let attributed_bytes = if whole_symbol {
                symbol.size
            } else {
                symbol
                    .size
                    .saturating_mul(u64::from(covered_lines))
                    .div_ceil(u64::from(symbol_lines))
            };
            mapping.attributed_bytes = Some(attributed_bytes);
            mapping.evidence.facts.push(if whole_symbol {
                MappingEvidenceFact::WholeSymbolAttribution
            } else {
                MappingEvidenceFact::ProportionalSymbolAttribution {
                    covered_lines,
                    symbol_lines,
                }
            });
        }
    }
}

/// Measure how much of a debug-attributed symbol's source-line extent one
/// persisted clone fragment covers. Source bytes are deliberately not guessed
/// from line numbers: the line extent is the only common evidence available
/// from both the source snapshot and DWARF frames.
///
/// The extent is counted over every source file the symbol's inline stack
/// names, not only the file the fragment lives in. A symbol built from
/// inlined bodies carries lines the fragment cannot contain, so covering the
/// fragment's own file is a share of the symbol rather than all of it. The
/// whole-symbol conclusion therefore stays reserved for a symbol whose frames
/// all name the fragment's file.
fn symbol_line_coverage(
    symbol: &codehelion_artifact::ArtifactSymbol,
    scan_root: &FilePath,
    fragment: &SourceFragmentIdentity,
) -> Option<(u32, u32, bool)> {
    let fragment_start = fragment.start_line?;
    let fragment_end = fragment.end_line?;
    let mut extents: BTreeMap<String, Option<(u32, u32)>> = BTreeMap::new();
    for frame in &symbol.inline_stack {
        let extent = extents
            .entry(uniformly_separated(&frame.source))
            .or_default();
        if let Some(line) = frame.line {
            *extent = Some(extent.map_or((line, line), |(start, end)| {
                (start.min(line), end.max(line))
            }));
        }
    }
    let mut fragment_file_extent: Option<(u32, u32)> = None;
    let mut symbol_lines = 0_u32;
    let mut other_files = false;
    for (source, extent) in &extents {
        if frame_path_matches(source, scan_root, fragment) {
            if let Some((start, end)) = *extent {
                fragment_file_extent = Some(
                    fragment_file_extent
                        .map_or((start, end), |range| (range.0.min(start), range.1.max(end))),
                );
            }
        } else {
            // Any other file names source the fragment does not hold, so the
            // symbol is more than this fragment even when those frames carry
            // no line of their own to divide by.
            other_files = true;
        }
        if let Some((start, end)) = *extent {
            symbol_lines = symbol_lines.saturating_add(end.saturating_sub(start).saturating_add(1));
        }
    }
    let (symbol_start, symbol_end) = fragment_file_extent?;
    let covered_start = fragment_start.max(symbol_start);
    let covered_end = fragment_end.min(symbol_end);
    if covered_start > covered_end {
        return None;
    }
    let covered_lines = covered_end.saturating_sub(covered_start).saturating_add(1);
    Some((
        covered_lines,
        symbol_lines,
        !other_files && fragment_start <= symbol_start && fragment_end >= symbol_end,
    ))
}

fn frame_path_matches(
    source_path: &str,
    scan_root: &FilePath,
    fragment: &SourceFragmentIdentity,
) -> bool {
    paths_match(source_path, scan_root, &fragment.file_path)
}

pub(in crate::artifact) fn enrich_call_graph_evidence(
    artifact: &ArtifactIr,
    sources: &SourceLocationIndex<'_>,
    resolved_calls: &[SourceResolvedCall],
    mappings: &mut [ArtifactAnalysisMapping],
) {
    let symbol_names: BTreeMap<_, _> = artifact
        .symbols
        .iter()
        .filter_map(|symbol| {
            symbol
                .name
                .as_deref()
                .and_then(canonical_symbol_name)
                .map(|name| (symbol.fingerprint.as_bytes(), name))
        })
        .collect();
    let mut artifact_targets: BTreeMap<_, BTreeSet<String>> = BTreeMap::new();
    for call in &artifact.calls {
        let Some(target) = call
            .target
            .and_then(|target| symbol_names.get(&target.as_bytes()))
        else {
            continue;
        };
        artifact_targets
            .entry(call.caller.as_bytes())
            .or_default()
            .insert(target.clone());
    }
    let mut source_targets: BTreeMap<_, BTreeSet<String>> = BTreeMap::new();
    for call in resolved_calls {
        let Some(target) = canonical_symbol_name(&call.target_name) else {
            continue;
        };
        for unit in sources.units_at(&call.file_path, Some(call.line)) {
            source_targets
                .entry((
                    source_kind_order(ArtifactAnalysisSourceKind::Unit),
                    *unit.fingerprint.as_bytes(),
                    unit.build_variant_fingerprint,
                ))
                .or_default()
                .insert(target.clone());
        }
        for fragment in sources.fragments_at(&call.file_path, Some(call.line)) {
            source_targets
                .entry((
                    source_kind_order(ArtifactAnalysisSourceKind::Fragment),
                    *fragment.fingerprint.as_bytes(),
                    fragment.build_variant_fingerprint,
                ))
                .or_default()
                .insert(target.clone());
        }
    }
    for mapping in mappings {
        if mapping
            .evidence
            .facts
            .iter()
            .any(|fact| matches!(fact, MappingEvidenceFact::CallGraphNeighborhood))
        {
            continue;
        }
        let Some(artifact) = artifact_targets.get(&mapping.artifact_symbol_fingerprint) else {
            continue;
        };
        let Some(source) = source_targets.get(&(
            source_kind_order(mapping.source_kind),
            mapping.source_fingerprint,
            mapping.source_build_variant_fingerprint,
        )) else {
            continue;
        };
        if !artifact.is_disjoint(source) {
            mapping
                .evidence
                .facts
                .push(MappingEvidenceFact::CallGraphNeighborhood);
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate aggregation and mapping construction must share the exact same evidence scope"
)]
pub(in crate::artifact) fn correlate_generic_origin(
    symbol: &codehelion_artifact::ArtifactSymbol,
    sources: &SourceLocationIndex<'_>,
    instantiations: &InstantiationIndex<'_>,
    artifact_variant: BuildVariantFingerprint,
) -> Vec<ArtifactAnalysisMapping> {
    let Some(artifact_name) = symbol.name.as_deref() else {
        return Vec::new();
    };
    let rust_key = normalized_generic_instantiation_key(artifact_name);
    let clang_key = normalized_clang_template_display_name(artifact_name);
    let clang_owner_key = normalized_clang_template_owner_name(artifact_name);
    if rust_key.is_none() && clang_key.is_none() && clang_owner_key.is_none() {
        return Vec::new();
    }
    let mut unit_candidates = BTreeMap::new();
    let mut fragment_candidates = BTreeMap::new();
    for (instantiation, matches_clang_owner_key) in instantiations.matching(
        rust_key.as_deref(),
        clang_key.as_deref(),
        clang_owner_key.as_deref(),
    ) {
        for unit in sources.generic_units_at(instantiation, matches_clang_owner_key) {
            unit_candidates
                .entry((
                    source_unit_instance_fingerprint(unit),
                    unit.build_variant_fingerprint,
                    instantiation.instantiation_key.clone(),
                    instantiation.definition.clone(),
                ))
                .or_insert_with(|| (unit, BTreeSet::new()))
                .1
                .insert(instantiation.translation_unit.clone());
        }
        for fragment in sources.fragments_at(&instantiation.file_path, Some(instantiation.line)) {
            fragment_candidates
                .entry((
                    fragment.finding_id,
                    fragment.build_variant_fingerprint,
                    instantiation.instantiation_key.clone(),
                    instantiation.definition.clone(),
                ))
                .or_insert_with(|| (fragment, BTreeSet::new()))
                .1
                .insert(instantiation.translation_unit.clone());
        }
    }
    let unit_candidate_count = u32::try_from(
        unit_candidates
            .keys()
            .map(|(fingerprint, variant, _, _)| (*fingerprint, *variant))
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap_or(u32::MAX);
    let fragment_candidate_count = u32::try_from(
        fragment_candidates
            .keys()
            .map(|(finding, variant, _, _)| (*finding, *variant))
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .unwrap_or(u32::MAX);
    let mut mappings = Vec::new();
    for ((_, _, instantiation_key, definition), (unit, translation_units)) in unit_candidates {
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: *unit.fingerprint.as_bytes(),
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            evidence: MappingEvidence::new(
                vec![MappingEvidenceFact::GenericOrigin {
                    definition,
                    instantiation_key,
                    translation_units: translation_units.into_iter().collect(),
                }],
                unit_candidate_count,
                false,
            ),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    for ((_, _, instantiation_key, definition), (fragment, translation_units)) in
        fragment_candidates
    {
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: *fragment.fingerprint.as_bytes(),
            source_instance_fingerprint: *fragment.finding_id.as_bytes(),
            source_build_variant_fingerprint: fragment.build_variant_fingerprint,
            evidence: MappingEvidence::new(
                vec![MappingEvidenceFact::GenericOrigin {
                    definition,
                    instantiation_key,
                    translation_units: translation_units.into_iter().collect(),
                }],
                fragment_candidate_count,
                false,
            ),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    mappings
}

#[allow(
    clippy::too_many_lines,
    reason = "name candidates retain macro provenance without collapsing competing source identities"
)]
pub(in crate::artifact) fn correlate_symbol_name(
    symbol: &codehelion_artifact::ArtifactSymbol,
    sources: &SourceLocationIndex<'_>,
    resolved_symbols: &ResolvedSymbolIndex<'_>,
    artifact_variant: BuildVariantFingerprint,
) -> Vec<ArtifactAnalysisMapping> {
    let Some(artifact_name) = symbol.name.as_deref().and_then(canonical_symbol_name) else {
        return Vec::new();
    };
    let mut unit_candidates = Vec::new();
    let mut fragment_candidates = Vec::new();
    // Candidates are collected per occurrence, never per content identity.
    // Content-identical declarations are exactly what this tool reports, and
    // keying on the shared content fingerprint would keep one of them and
    // report the rest as reached by no artifact evidence.
    let mut seen_units = BTreeSet::new();
    let mut seen_fragments = BTreeSet::new();
    // The index answers with the definitions whose canonical spelling is this
    // symbol's, so the name comparison is already settled here.
    for source_symbol in resolved_symbols.named(&artifact_name) {
        let source_name = artifact_name.clone();
        for unit in sources.units_at(&source_symbol.file_path, Some(source_symbol.line)) {
            if seen_units.insert((
                source_unit_instance_fingerprint(unit),
                unit.build_variant_fingerprint,
            )) {
                unit_candidates.push((
                    unit,
                    source_name.clone(),
                    source_symbol
                        .macro_definition
                        .as_ref()
                        .map(|anchor| anchor.file_path.clone()),
                ));
            }
        }
        for fragment in sources.fragments_at(&source_symbol.file_path, Some(source_symbol.line)) {
            if seen_fragments.insert((fragment.finding_id, fragment.build_variant_fingerprint)) {
                fragment_candidates.push((
                    fragment,
                    source_name.clone(),
                    source_symbol
                        .macro_definition
                        .as_ref()
                        .map(|anchor| anchor.file_path.clone()),
                ));
            }
        }
    }
    if unit_candidates.is_empty() && fragment_candidates.is_empty() {
        unit_candidates.extend(
            sources
                .units_named(&artifact_name)
                .into_iter()
                .map(|unit| (unit, artifact_name.clone(), None)),
        );
    }
    let unit_candidate_count = u32::try_from(unit_candidates.len()).unwrap_or(u32::MAX);
    let fragment_candidate_count = u32::try_from(fragment_candidates.len()).unwrap_or(u32::MAX);
    let mut mappings = Vec::new();
    for (unit, source_name, macro_definition) in unit_candidates {
        let mut facts = vec![MappingEvidenceFact::SymbolName {
            source_symbol: source_name,
            artifact_symbol: artifact_name.clone(),
        }];
        if let Some(definition_path) = macro_definition {
            facts.push(MappingEvidenceFact::MacroOrigin { definition_path });
        }
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: *unit.fingerprint.as_bytes(),
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            evidence: MappingEvidence::new(facts, unit_candidate_count, false),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    for (fragment, source_name, macro_definition) in fragment_candidates {
        let mut facts = vec![MappingEvidenceFact::SymbolName {
            source_symbol: source_name,
            artifact_symbol: artifact_name.clone(),
        }];
        if let Some(definition_path) = macro_definition {
            facts.push(MappingEvidenceFact::MacroOrigin { definition_path });
        }
        mappings.push(ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: *fragment.fingerprint.as_bytes(),
            source_instance_fingerprint: *fragment.finding_id.as_bytes(),
            source_build_variant_fingerprint: fragment.build_variant_fingerprint,
            evidence: MappingEvidence::new(facts, fragment_candidate_count, false),
            attributed_bytes: None,
            build_variant_fingerprint: artifact_variant,
        });
    }
    mappings
}

/// Merge independent fallback candidates without guessing which extractor won.
///
/// A compiler-reported generic origin and a demangled name normally reinforce
/// the same source identity. If their candidate sets are disjoint, both sets
/// remain visible and their evidence is marked as conflicting. This preserves
/// the many-to-many correspondence instead of selecting a plausible-looking
/// single best candidate.
pub(in crate::artifact) fn combine_fallback_mappings(
    mut generic_mappings: Vec<ArtifactAnalysisMapping>,
    mut name_mappings: Vec<ArtifactAnalysisMapping>,
) -> Vec<ArtifactAnalysisMapping> {
    if generic_mappings.is_empty() {
        return name_mappings;
    }
    if name_mappings.is_empty() {
        return generic_mappings;
    }

    let generic_keys: BTreeSet<_> = generic_mappings.iter().map(mapping_source_key).collect();
    let name_keys: BTreeSet<_> = name_mappings.iter().map(mapping_source_key).collect();
    if generic_keys.is_disjoint(&name_keys) {
        for mapping in generic_mappings.iter_mut().chain(&mut name_mappings) {
            mapping.evidence.has_conflict = true;
        }
        generic_mappings.extend(name_mappings);
        return generic_mappings;
    }

    for generic in &mut generic_mappings {
        let generic_key = mapping_source_key(generic);
        for name in name_mappings
            .iter()
            .filter(|name| mapping_source_key(name) == generic_key)
        {
            generic.evidence.facts.extend(name.evidence.facts.clone());
            generic.evidence.candidate_count = generic
                .evidence
                .candidate_count
                .max(name.evidence.candidate_count);
        }
    }
    generic_mappings.extend(
        name_mappings
            .into_iter()
            .filter(|mapping| !generic_keys.contains(&mapping_source_key(mapping))),
    );
    generic_mappings
}

/// What identifies the source side of one correspondence.
///
/// The build variant is part of it and is spelled as itself: the same source
/// occurrence read under two builds is two correspondences, and a key that
/// held the variant as bare bytes beside two code identities could be built
/// with them in any order.
const fn mapping_source_key(
    mapping: &ArtifactAnalysisMapping,
) -> (u8, [u8; 16], [u8; 16], BuildVariantFingerprint) {
    (
        source_kind_order(mapping.source_kind),
        mapping.source_fingerprint,
        mapping.source_instance_fingerprint,
        mapping.source_build_variant_fingerprint,
    )
}
