//! Correlation fallback matching and attribution.

use super::mapping::source_unit_instance_fingerprint;
use super::{
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactIr, BTreeMap, BTreeSet, FilePath,
    MappingEvidence, MappingEvidenceFact, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
    SourceFragmentIdentity, SourceInstantiation, SourceResolvedCall, SourceResolvedSymbol,
    SourceUnitIdentity, source_kind_order,
};

/// The scan's source occurrences, prepared once for repeated lookups.
///
/// Every correlation pass asks the same two questions for each artifact symbol,
/// inline frame, resolved call, and source-map token: which units and which
/// clone fragments does this file and line name. Answering them by walking the
/// whole scan each time makes the work the product of the artifact size and the
/// scan size. The lists are therefore grouped by file once, and each lookup
/// narrows to one file before the exact predicates below decide.
///
/// The grouping is only a narrowing step: a file group is a superset of the
/// matches, and membership is still settled by the same `source_*_matches`
/// predicates every other caller uses, so no comparison rule exists twice.
pub(in crate::artifact) struct SourceLocationIndex<'source> {
    scan_root: &'source FilePath,
    units: &'source [SourceUnitIdentity],
    fragments: &'source [SourceFragmentIdentity],
    scan_root_prefix: String,
    units_by_file: BTreeMap<String, Vec<usize>>,
    units_by_name: BTreeMap<String, Vec<usize>>,
    fragments_by_file: BTreeMap<String, Vec<usize>>,
}

impl<'source> SourceLocationIndex<'source> {
    pub(in crate::artifact) fn new(
        scan_root: &'source FilePath,
        units: &'source [SourceUnitIdentity],
        fragments: &'source [SourceFragmentIdentity],
    ) -> Self {
        let mut units_by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut units_by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (position, unit) in units.iter().enumerate() {
            units_by_file
                .entry(uniformly_separated(&unit.file_path))
                .or_default()
                .push(position);
            if let Some(name) = unit.name.as_deref().and_then(canonical_symbol_name) {
                units_by_name.entry(name).or_default().push(position);
            }
        }
        let mut fragments_by_file: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (position, fragment) in fragments.iter().enumerate() {
            fragments_by_file
                .entry(uniformly_separated(&fragment.file_path))
                .or_default()
                .push(position);
        }
        let mut scan_root_prefix = uniformly_separated(&scan_root.to_string_lossy());
        if scan_root_prefix.ends_with('/') {
            scan_root_prefix.pop();
        }
        Self {
            scan_root,
            units,
            fragments,
            scan_root_prefix,
            units_by_file,
            units_by_name,
            fragments_by_file,
        }
    }

    /// The two spellings under which a scanned file can be recorded.
    ///
    /// Debug information names a file either the way the project spells it or
    /// with the scan root in front, and [`paths_match`] accepts both readings.
    fn file_keys(&self, source_path: &str) -> (String, Option<String>) {
        let direct = uniformly_separated(source_path);
        let inside_root = direct
            .strip_prefix(self.scan_root_prefix.as_str())
            .and_then(|inside| inside.strip_prefix('/'))
            .map(ToOwned::to_owned);
        (direct, inside_root)
    }

    /// Positions recorded for one file, in the order the scan reported them.
    fn positions(
        index: &BTreeMap<String, Vec<usize>>,
        keys: &(String, Option<String>),
    ) -> Vec<usize> {
        let mut positions = index.get(&keys.0).cloned().unwrap_or_default();
        if let Some(inside_root) = &keys.1 {
            positions.extend(index.get(inside_root).into_iter().flatten().copied());
        }
        positions.sort_unstable();
        positions
    }

    fn units_in_file(
        &self,
        source_path: &str,
    ) -> impl Iterator<Item = &'source SourceUnitIdentity> {
        let keys = self.file_keys(source_path);
        Self::positions(&self.units_by_file, &keys)
            .into_iter()
            .filter_map(|position| self.units.get(position))
    }

    fn fragments_in_file(
        &self,
        source_path: &str,
    ) -> impl Iterator<Item = &'source SourceFragmentIdentity> {
        let keys = self.file_keys(source_path);
        Self::positions(&self.fragments_by_file, &keys)
            .into_iter()
            .filter_map(|position| self.fragments.get(position))
    }

    /// Units whose file and line extent contain one artifact-side location.
    pub(in crate::artifact) fn units_at(
        &self,
        source_path: &str,
        source_line: Option<u32>,
    ) -> Vec<&'source SourceUnitIdentity> {
        self.units_in_file(source_path)
            .filter(|unit| source_unit_matches(source_path, source_line, self.scan_root, unit))
            .collect()
    }

    /// Clone fragments whose file and line extent contain one location.
    pub(in crate::artifact) fn fragments_at(
        &self,
        source_path: &str,
        source_line: Option<u32>,
    ) -> Vec<&'source SourceFragmentIdentity> {
        self.fragments_in_file(source_path)
            .filter(|fragment| {
                source_fragment_matches(source_path, source_line, self.scan_root, fragment)
            })
            .collect()
    }

    /// Units a compiler's generic-definition anchor names.
    fn generic_units_at(
        &self,
        instantiation: &SourceInstantiation,
        include_definition_extent: bool,
    ) -> Vec<&'source SourceUnitIdentity> {
        self.units_in_file(&instantiation.file_path)
            .filter(|unit| {
                source_generic_unit_matches(
                    &instantiation.file_path,
                    Some(instantiation.line),
                    self.scan_root,
                    unit,
                ) || include_definition_extent
                    && source_template_definition_contains_unit(instantiation, self.scan_root, unit)
            })
            .collect()
    }

    /// Units whose declared name matches one artifact symbol name.
    fn units_named(&self, artifact_name: &str) -> Vec<&'source SourceUnitIdentity> {
        self.units_by_name
            .get(artifact_name)
            .into_iter()
            .flatten()
            .filter_map(|position| self.units.get(*position))
            .collect()
    }
}

/// Compiler-reported specializations, prepared for per-symbol lookups.
///
/// The three normalized spellings an artifact symbol can be compared against
/// are derived once per specialization instead of once per symbol pairing.
pub(in crate::artifact) struct InstantiationIndex<'source> {
    instantiations: &'source [SourceInstantiation],
    by_instantiation_key: BTreeMap<String, Vec<usize>>,
    by_template_display: BTreeMap<String, Vec<usize>>,
    by_template_owner: BTreeMap<String, Vec<usize>>,
}

impl<'source> InstantiationIndex<'source> {
    pub(in crate::artifact) fn new(instantiations: &'source [SourceInstantiation]) -> Self {
        let mut by_instantiation_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_template_display: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut by_template_owner: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (position, instantiation) in instantiations.iter().enumerate() {
            if let Some(key) =
                normalized_generic_instantiation_key(&instantiation.instantiation_key)
            {
                by_instantiation_key.entry(key).or_default().push(position);
            }
            let Some(match_key) = instantiation.artifact_match_key.as_deref() else {
                continue;
            };
            if let Some(key) = normalized_clang_template_display_name(match_key) {
                by_template_display.entry(key).or_default().push(position);
            }
            if let Some(key) = normalized_clang_template_owner_name(match_key) {
                by_template_owner.entry(key).or_default().push(position);
            }
        }
        Self {
            instantiations,
            by_instantiation_key,
            by_template_display,
            by_template_owner,
        }
    }

    /// Specializations one artifact symbol name can be compared against.
    ///
    /// Each answer carries whether it was reached through a class-template
    /// owner, which is the only evidence that lets a member body be attributed
    /// through the compiler's definition extent.
    fn matching(
        &self,
        rust_key: Option<&str>,
        template_display_key: Option<&str>,
        template_owner_key: Option<&str>,
    ) -> Vec<(&'source SourceInstantiation, bool)> {
        let mut matched: BTreeMap<usize, bool> = BTreeMap::new();
        for (index, key) in [
            (&self.by_instantiation_key, rust_key),
            (&self.by_template_display, template_display_key),
        ] {
            for position in key.and_then(|key| index.get(key)).into_iter().flatten() {
                matched.entry(*position).or_insert(false);
            }
        }
        for position in template_owner_key
            .and_then(|key| self.by_template_owner.get(key))
            .into_iter()
            .flatten()
        {
            matched.insert(*position, true);
        }
        matched
            .into_iter()
            .filter_map(|(position, owner)| {
                self.instantiations
                    .get(position)
                    .map(|instantiation| (instantiation, owner))
            })
            .collect()
    }
}

/// Compiler-resolved definitions, grouped by the name they can be matched on.
pub(in crate::artifact) struct ResolvedSymbolIndex<'source> {
    resolved_symbols: &'source [SourceResolvedSymbol],
    by_name: BTreeMap<String, Vec<usize>>,
}

impl<'source> ResolvedSymbolIndex<'source> {
    pub(in crate::artifact) fn new(resolved_symbols: &'source [SourceResolvedSymbol]) -> Self {
        let mut by_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (position, resolved) in resolved_symbols.iter().enumerate() {
            if let Some(name) = canonical_symbol_name(&resolved.name) {
                by_name.entry(name).or_default().push(position);
            }
        }
        Self {
            resolved_symbols,
            by_name,
        }
    }

    fn named(&self, artifact_name: &str) -> Vec<&'source SourceResolvedSymbol> {
        self.by_name
            .get(artifact_name)
            .into_iter()
            .flatten()
            .filter_map(|position| self.resolved_symbols.get(*position))
            .collect()
    }
}

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
        .map(|fragment| (fragment.finding_id, fragment))
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
                    unit.fingerprint,
                    unit.build_variant_fingerprint,
                ))
                .or_default()
                .insert(target.clone());
        }
        for fragment in sources.fragments_at(&call.file_path, Some(call.line)) {
            source_targets
                .entry((
                    source_kind_order(ArtifactAnalysisSourceKind::Fragment),
                    fragment.fingerprint,
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
    artifact_variant: [u8; 16],
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
            source_fingerprint: unit.fingerprint,
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
            source_fingerprint: fragment.fingerprint,
            source_instance_fingerprint: fragment.finding_id,
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
    artifact_variant: [u8; 16],
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
            source_fingerprint: unit.fingerprint,
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
            source_fingerprint: fragment.fingerprint,
            source_instance_fingerprint: fragment.finding_id,
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

const fn mapping_source_key(
    mapping: &ArtifactAnalysisMapping,
) -> (u8, [u8; 16], [u8; 16], [u8; 16]) {
    (
        source_kind_order(mapping.source_kind),
        mapping.source_fingerprint,
        mapping.source_instance_fingerprint,
        mapping.source_build_variant_fingerprint,
    )
}

pub(in crate::artifact) fn canonical_symbol_name(name: &str) -> Option<String> {
    let before_signature = name.trim().split('(').next()?.trim();
    let leaf = before_signature.rsplit("::").next()?.trim();
    let without_arguments = leaf.split('<').next()?.trim();
    (!without_arguments.is_empty()).then(|| without_arguments.to_owned())
}

pub(in crate::artifact) fn normalized_generic_instantiation_key(name: &str) -> Option<String> {
    let compact: String = name
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    (compact.contains('<') && compact.ends_with('>')).then(|| compact.replace("::<", "<"))
}

/// Normalize a C++ function-template display name for a source/artifact
/// comparison. Both inputs are compiler-produced: Clang's display name is
/// tagged by the helper, while the artifact backend has already demangled its
/// symbol. This deliberately rejects class templates and ordinary functions;
/// neither form has enough evidence to be a generic-origin correspondence.
pub(in crate::artifact) fn normalized_clang_template_display_name(name: &str) -> Option<String> {
    let tagged_source = name.starts_with("clang-display-v1:");
    let name = name
        .strip_prefix("clang-display-v1:")
        .unwrap_or(name)
        .trim();
    let open = name.find('(')?;
    let close = name.rfind(')')?;
    if close < open || (!name[..open].contains('<') && !tagged_source) {
        return None;
    }
    let before_parameters = name[..open].trim();
    let qualified = qualified_cpp_symbol_name(before_parameters);
    let mut normalized = String::with_capacity(name.len());
    let mut depth = 0_u32;
    for character in qualified.chars() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => normalized.push(character),
            _ => {}
        }
    }
    normalized.push_str(name.get(open..=close)?);
    (!normalized.is_empty()).then_some(normalized)
}

/// Normalize a C++ class-template specialization that owns one demangled
/// member function. The source key is the fully qualified class display name;
/// the artifact key is the owner preceding the member name. The comparison is
/// exact after whitespace and integral-literal suffix normalization, so a
/// member of `Buffer<int, 8>` cannot be attributed to `Buffer<int, 4>`.
pub(in crate::artifact) fn normalized_clang_template_owner_name(name: &str) -> Option<String> {
    let tagged_source = name.starts_with("clang-display-v1:");
    let name = name
        .strip_prefix("clang-display-v1:")
        .unwrap_or(name)
        .trim();
    let owner = if tagged_source {
        (name.contains('<') && name.ends_with('>')).then_some(name)
    } else {
        let open = cpp_member_parameter_open(name)?;
        let before_parameters = name[..open].trim();
        let qualified = qualified_cpp_symbol_name(before_parameters);
        let (owner, _) = qualified.rsplit_once("::")?;
        (owner.contains('<') && owner.ends_with('>')).then_some(owner)
    }?;
    Some(normalize_cpp_template_owner(owner))
}

/// Locate the member-function parameter list outside template arguments.
///
/// A non-type template argument may itself contain a cast such as
/// `(unsigned long)4`, which is not the member-function parameter list.
pub(in crate::artifact) fn cpp_member_parameter_open(name: &str) -> Option<usize> {
    let mut template_depth = 0_u32;
    for (index, character) in name.char_indices() {
        match character {
            '<' => template_depth = template_depth.saturating_add(1),
            '>' => template_depth = template_depth.saturating_sub(1),
            '(' if template_depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

/// Remove a C++ return type without mistaking whitespace inside `<...>` for
/// the separator before the qualified function name.
pub(in crate::artifact) fn qualified_cpp_symbol_name(spelling: &str) -> &str {
    let mut depth = 0_u32;
    let mut separator = None;
    for (index, character) in spelling.char_indices() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 && character.is_whitespace() => separator = Some(index),
            _ => {}
        }
    }
    separator.map_or(spelling, |index| spelling[index..].trim_start())
}

/// Remove formatting and the ABI's harmless decimal integer literal suffixes.
pub(in crate::artifact) fn normalize_cpp_template_owner(owner: &str) -> String {
    let compact: String = owner
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    // Demanglers may spell a non-type integral template argument with the
    // ABI's explicit type cast, e.g. `Buffer<int, (unsigned long)4>`.  This
    // function only receives the template owner (never parameter types), so
    // removing those integer casts leaves the specialization identity intact.
    let compact = [
        "(unsignedlonglong)",
        "(unsignedlong)",
        "(unsignedint)",
        "(longlong)",
        "(long)",
        "(int)",
    ]
    .into_iter()
    .fold(compact, |normalized, cast| normalized.replace(cast, ""));
    let characters: Vec<_> = compact.chars().collect();
    let mut normalized = String::with_capacity(compact.len());
    let mut index = 0;
    while index < characters.len() {
        if !characters[index].is_ascii_digit() {
            normalized.push(characters[index]);
            index += 1;
            continue;
        }
        let digits_start = index;
        while index < characters.len() && characters[index].is_ascii_digit() {
            index += 1;
        }
        normalized.extend(characters[digits_start..index].iter());
        let suffix_start = index;
        while index < characters.len() && matches!(characters[index], 'u' | 'U' | 'l' | 'L') {
            index += 1;
        }
        if suffix_start == index
            || index < characters.len() && !matches!(characters[index], ',' | '>' | ')')
        {
            normalized.extend(characters[suffix_start..index].iter());
        }
    }
    normalized
}

/// Restate a path so its components are separated by `/`.
///
/// The two sides of every comparison below are written by different programs:
/// debug information produced on Windows names a file with `\`, while the scan
/// records the path the way the project spells it. Whether a separator is a
/// separator is not a question either side's spelling gets to answer
/// differently.
pub(in crate::artifact) fn uniformly_separated(path: &str) -> String {
    path.replace('\\', "/")
}

/// Whether the artifact-side `source_path` names the scanned file
/// `recorded_path`.
///
/// One rule for every path identity question this module asks, so the same
/// pair of paths cannot be a match where a symbol is being placed and a
/// mismatch where its bytes are being attributed. The recorded path is relative
/// to the scan root, and debug information carries it either way, so both
/// readings are accepted.
pub(in crate::artifact) fn paths_match(
    source_path: &str,
    scan_root: &FilePath,
    recorded_path: &str,
) -> bool {
    let source_path = uniformly_separated(source_path);
    let recorded_path = uniformly_separated(recorded_path);
    if source_path == recorded_path {
        return true;
    }
    let scan_root = uniformly_separated(&scan_root.to_string_lossy());
    let scan_root = scan_root.strip_suffix('/').unwrap_or(&scan_root);
    source_path
        .strip_prefix(scan_root)
        .and_then(|inside| inside.strip_prefix('/'))
        .is_some_and(|inside| inside == recorded_path)
}

pub(in crate::artifact) fn source_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    if !paths_match(source_path, scan_root, &unit.file_path) {
        return false;
    }
    match (source_line, unit.start_line, unit.end_line) {
        (Some(line), Some(start), Some(end)) => start <= line && line <= end,
        _ => true,
    }
}

/// Match a compiler's generic-definition anchor to a source unit.
///
/// Clang reports a function template at its declaration line, whereas the
/// structural frontend anchors its function unit at the opening brace on the
/// following line.  That one-line difference is syntax-derived rather than a
/// fuzzy location match, and is limited to generic-origin evidence.
pub(in crate::artifact) fn source_generic_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    if source_unit_matches(source_path, source_line, scan_root, unit) {
        return true;
    }
    let (Some(line), Some(start_line)) = (source_line, unit.start_line) else {
        return false;
    };
    paths_match(source_path, scan_root, &unit.file_path) && line.checked_add(1) == Some(start_line)
}

/// Whether a source unit is wholly inside a class-template definition.
///
/// Class template instantiations are anchored at the class declaration, while
/// emitted symbols commonly name an inline member body.  The compiler-supplied
/// definition extent lets this match that member without guessing from its
/// short name.  Both endpoints must be present, so a partial range remains
/// unmapped.
pub(in crate::artifact) fn source_template_definition_contains_unit(
    instantiation: &SourceInstantiation,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    let (Some(definition_end_line), Some(unit_start_line), Some(unit_end_line)) = (
        instantiation.definition_end_line,
        unit.start_line,
        unit.end_line,
    ) else {
        return false;
    };
    paths_match(&instantiation.file_path, scan_root, &unit.file_path)
        && instantiation.line <= unit_start_line
        && unit_end_line <= definition_end_line
}

pub(in crate::artifact) fn source_fragment_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    fragment: &SourceFragmentIdentity,
) -> bool {
    if !paths_match(source_path, scan_root, &fragment.file_path) {
        return false;
    }
    match (source_line, fragment.start_line, fragment.end_line) {
        (Some(line), Some(start), Some(end)) => start <= line && line <= end,
        // A file path alone cannot select a clone fragment: treating every
        // fragment in the file as a DWARF match would make a missing line
        // look like evidence and could attribute bytes to an arbitrary
        // duplicate. Whole units may remain an explicitly ambiguous mapping,
        // but fragment-level attribution is fail-closed.
        _ => false,
    }
}
