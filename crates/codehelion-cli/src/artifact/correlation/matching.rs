//! Correlation fallback matching and attribution.

use super::mapping::source_unit_instance_fingerprint;
use super::{
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactIr, BTreeMap, BTreeSet, FilePath,
    MappingEvidence, MappingEvidenceFact, SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION,
    SourceFragmentIdentity, SourceInstantiation, SourceResolvedCall, SourceResolvedSymbol,
    SourceUnitIdentity, source_kind_order,
};

/// Attribute a symbol's observed bytes only when one exact fragment mapping
/// accounts for it. Units can contain fragments, so unit mappings neither
/// create nor block this fragment-level split.
pub(in crate::artifact) fn assign_unambiguous_fragment_bytes(
    artifact: &ArtifactIr,
    mappings: &mut [ArtifactAnalysisMapping],
) {
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
            mappings[*index].attributed_bytes = Some(symbol.size);
        }
    }
}

pub(in crate::artifact) fn enrich_call_graph_evidence(
    artifact: &ArtifactIr,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
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
        for unit in units
            .iter()
            .filter(|unit| source_unit_matches(&call.file_path, Some(call.line), scan_root, unit))
        {
            source_targets
                .entry((
                    source_kind_order(ArtifactAnalysisSourceKind::Unit),
                    unit.fingerprint,
                    unit.build_variant_fingerprint,
                ))
                .or_default()
                .insert(target.clone());
        }
        for fragment in fragments.iter().filter(|fragment| {
            source_fragment_matches(&call.file_path, Some(call.line), scan_root, fragment)
        }) {
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
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    instantiations: &[SourceInstantiation],
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
    for instantiation in instantiations {
        let matches_rust_key = rust_key.as_deref().is_some_and(|artifact_key| {
            normalized_generic_instantiation_key(&instantiation.instantiation_key).as_deref()
                == Some(artifact_key)
        });
        let matches_clang_key = clang_key.as_deref().is_some_and(|artifact_key| {
            instantiation
                .artifact_match_key
                .as_deref()
                .and_then(normalized_clang_template_display_name)
                .as_deref()
                == Some(artifact_key)
        });
        let matches_clang_owner_key = clang_owner_key.as_deref().is_some_and(|artifact_key| {
            instantiation
                .artifact_match_key
                .as_deref()
                .and_then(normalized_clang_template_owner_name)
                .as_deref()
                == Some(artifact_key)
        });
        if !matches_rust_key && !matches_clang_key && !matches_clang_owner_key {
            continue;
        }
        for unit in units.iter().filter(|unit| {
            source_generic_unit_matches(
                &instantiation.file_path,
                Some(instantiation.line),
                scan_root,
                unit,
            ) || matches_clang_owner_key
                && source_template_definition_contains_unit(instantiation, scan_root, unit)
        }) {
            unit_candidates
                .entry((
                    unit.fingerprint,
                    unit.build_variant_fingerprint,
                    instantiation.instantiation_key.clone(),
                    instantiation.definition.clone(),
                ))
                .or_insert_with(|| (unit, BTreeSet::new()))
                .1
                .insert(instantiation.translation_unit.clone());
        }
        for fragment in fragments.iter().filter(|fragment| {
            source_fragment_matches(
                &instantiation.file_path,
                Some(instantiation.line),
                scan_root,
                fragment,
            )
        }) {
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
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    resolved_symbols: &[SourceResolvedSymbol],
    artifact_variant: [u8; 16],
) -> Vec<ArtifactAnalysisMapping> {
    let Some(artifact_name) = symbol.name.as_deref().and_then(canonical_symbol_name) else {
        return Vec::new();
    };
    let mut unit_candidates = Vec::new();
    let mut fragment_candidates = Vec::new();
    let mut seen_units = BTreeSet::new();
    let mut seen_fragments = BTreeSet::new();
    for source_symbol in resolved_symbols {
        let Some(source_name) = canonical_symbol_name(&source_symbol.name) else {
            continue;
        };
        if source_name != artifact_name {
            continue;
        }
        for unit in units.iter().filter(|unit| {
            source_unit_matches(
                &source_symbol.file_path,
                Some(source_symbol.line),
                scan_root,
                unit,
            )
        }) {
            if seen_units.insert((unit.fingerprint, unit.build_variant_fingerprint)) {
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
        for fragment in fragments.iter().filter(|fragment| {
            source_fragment_matches(
                &source_symbol.file_path,
                Some(source_symbol.line),
                scan_root,
                fragment,
            )
        }) {
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
        unit_candidates.extend(units.iter().filter_map(|unit| {
            unit.name
                .as_deref()
                .and_then(canonical_symbol_name)
                .filter(|source_name| source_name == &artifact_name)
                .map(|source_name| (unit, source_name, None))
        }));
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

pub(in crate::artifact) fn source_unit_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    unit: &SourceUnitIdentity,
) -> bool {
    let source_path = FilePath::new(source_path);
    let unit_path = FilePath::new(&unit.file_path);
    if source_path != unit_path && source_path != scan_root.join(unit_path) {
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
    let source_path = FilePath::new(source_path);
    let unit_path = FilePath::new(&unit.file_path);
    (source_path == unit_path || source_path == scan_root.join(unit_path))
        && line.checked_add(1) == Some(start_line)
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
    let source_path = FilePath::new(&instantiation.file_path);
    let unit_path = FilePath::new(&unit.file_path);
    (source_path == unit_path || source_path == scan_root.join(unit_path))
        && instantiation.line <= unit_start_line
        && unit_end_line <= definition_end_line
}

pub(in crate::artifact) fn source_fragment_matches(
    source_path: &str,
    source_line: Option<u32>,
    scan_root: &FilePath,
    fragment: &SourceFragmentIdentity,
) -> bool {
    let source_path = FilePath::new(source_path);
    let fragment_path = FilePath::new(&fragment.file_path);
    if source_path != fragment_path && source_path != scan_root.join(fragment_path) {
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
