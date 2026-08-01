//! Source-run loading, linker-map evidence, and debug-location correlation.

use super::matching::{
    assign_unambiguous_fragment_bytes, canonical_symbol_name, combine_fallback_mappings,
    correlate_generic_origin, correlate_symbol_name, enrich_call_graph_evidence,
    source_fragment_matches, source_unit_matches,
};
use super::{
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSource, ArtifactAnalysisUnmappedSourceReason,
    ArtifactAnalysisUnmappedSymbol, ArtifactIr, BTreeMap, BTreeSet, BuildVariantEvidence, Context,
    CorrelationRows, FilePath, MAX_LINKER_MAP_BYTES, MappingEvidence, MappingEvidenceFact, Result,
    SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION, SourceFragmentIdentity, SourceInstantiation,
    SourceResolvedCall, SourceResolvedSymbol, SourceUnitIdentity, Store, bail, fs,
    unmapped_reason_label,
};

pub(in crate::artifact) fn correlate_source_run(
    artifact: &ArtifactIr,
    source_run: Option<i64>,
    artifact_variant: Option<&BuildVariantEvidence>,
    linker_map: &[LinkerMapEntry],
    store: &Store,
) -> Result<CorrelationRows> {
    let Some(source_run) = source_run else {
        return Ok(CorrelationRows::default());
    };
    let artifact_variant = artifact_variant.ok_or_else(|| {
        anyhow::anyhow!("--source-run requires a build variant manifest for the artifact")
    })?;
    let origin = store
        .run_origin(source_run)
        .with_context(|| format!("loading source scan {source_run}"))?;
    let units = store
        .source_units(source_run)
        .with_context(|| format!("loading source units for scan {source_run}"))?;
    let fragments = store
        .source_clone_fragments(source_run)
        .with_context(|| format!("loading clone fragments for scan {source_run}"))?;
    let resolved_symbols = store
        .source_resolved_symbols(source_run)
        .with_context(|| format!("loading compiler symbols for scan {source_run}"))?;
    let instantiations = store
        .source_instantiations(source_run)
        .with_context(|| format!("loading compiler instantiations for scan {source_run}"))?;
    let resolved_calls = store
        .source_resolved_calls(source_run)
        .with_context(|| format!("loading compiler calls for scan {source_run}"))?;
    let mut rows = correlate_debug_locations(
        artifact,
        FilePath::new(&origin.root_path),
        &units,
        &fragments,
        &instantiations,
        &resolved_symbols,
        &resolved_calls,
        artifact_variant.fingerprint.as_bytes(),
    );
    enrich_linker_map_evidence(
        artifact,
        &units,
        linker_map,
        artifact_variant.fingerprint.as_bytes(),
        &mut rows,
    );
    Ok(rows)
}

/// One symbol-to-object placement recovered from a pre-existing linker map.
///
/// Linker addresses and map-line offsets deliberately do not leave this
/// boundary: the later correlation records only stable source and artifact
/// fingerprints plus this object-path evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::artifact) struct LinkerMapEntry {
    pub(in crate::artifact) symbol: String,
    pub(in crate::artifact) object_path: String,
}

/// Read a bounded local linker map without invoking the linker that produced it.
pub(in crate::artifact) fn read_linker_map(path: Option<&FilePath>) -> Result<Vec<LinkerMapEntry>> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading metadata for linker map {}", path.display()))?;
    if metadata.len() > MAX_LINKER_MAP_BYTES {
        bail!(
            "linker map {} is {} bytes, exceeding the {} byte input limit",
            path.display(),
            metadata.len(),
            MAX_LINKER_MAP_BYTES
        );
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("reading linker map {}", path.display()))?;
    Ok(parse_linker_map(&text))
}

/// Parse the symbol lines emitted by GNU-ld-compatible map files.
///
/// The parser intentionally accepts only a local object path paired with a
/// symbol. It does not infer a source identity from section addresses or a
/// linker-script expression.
pub(in crate::artifact) fn parse_linker_map(text: &str) -> Vec<LinkerMapEntry> {
    let mut entries = BTreeSet::new();
    let mut current_object = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let object = fields
            .iter()
            .find_map(|field| linker_map_object_path(field));
        if let Some(object) = object {
            current_object = Some(object.clone());
            if let (Some(section), Some(symbol)) = (
                fields
                    .first()
                    .and_then(|field| field.strip_prefix(".text.")),
                current_object.as_ref(),
            ) {
                entries.insert(LinkerMapEntry {
                    symbol: section.to_owned(),
                    object_path: symbol.clone(),
                });
            }
        }
        let Some(object_path) = current_object.as_ref() else {
            continue;
        };
        let Some(address) = fields.first() else {
            continue;
        };
        let Some(symbol) = fields.get(1) else {
            continue;
        };
        if is_linker_address(address) && !is_linker_address(symbol) && !symbol.starts_with('.') {
            entries.insert(LinkerMapEntry {
                symbol: (*symbol).to_owned(),
                object_path: object_path.clone(),
            });
        }
    }
    entries.into_iter().collect()
}

pub(in crate::artifact) fn linker_map_object_path(field: &str) -> Option<String> {
    let path = field.trim_matches(|character| matches!(character, '(' | ')'));
    let object = path.strip_suffix(".o")?;
    (!object.is_empty()).then(|| path.to_owned())
}

pub(in crate::artifact) fn is_linker_address(value: &str) -> bool {
    value.strip_prefix("0x").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_hexdigit())
    })
}

/// Add linker-map evidence to existing unit mappings or recover unmapped units.
///
/// A map object path must embed the scan-relative source path after removing
/// the final `.o` suffix, and the unit's declared name must agree with the
/// linker symbol. This covers conventional `CMake` and compiler output paths
/// without guessing from a basename. Equal candidates remain separate mappings
/// and therefore stay ambiguous.
#[allow(
    clippy::too_many_lines,
    reason = "linker-map candidates and existing mapping reconciliation share one evidence boundary"
)]
pub(in crate::artifact) fn enrich_linker_map_evidence(
    artifact: &ArtifactIr,
    units: &[SourceUnitIdentity],
    entries: &[LinkerMapEntry],
    artifact_variant: [u8; 16],
    rows: &mut CorrelationRows,
) {
    for symbol in &artifact.symbols {
        let Some(symbol_name) = symbol.name.as_deref().and_then(canonical_symbol_name) else {
            continue;
        };
        let mut candidates = BTreeMap::new();
        for entry in entries.iter().filter(|entry| {
            canonical_symbol_name(&entry.symbol).as_deref() == Some(symbol_name.as_str())
        }) {
            for unit in units.iter().filter(|unit| {
                linker_object_matches_source(&entry.object_path, &unit.file_path)
                    && unit
                        .name
                        .as_deref()
                        .and_then(canonical_symbol_name)
                        .as_deref()
                        == Some(symbol_name.as_str())
            }) {
                candidates
                    .entry((
                        unit.fingerprint,
                        source_unit_instance_fingerprint(unit),
                        unit.build_variant_fingerprint,
                    ))
                    .or_insert_with(|| (unit, entry.object_path.clone()));
            }
        }
        let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
        if candidate_count == 0 {
            continue;
        }
        let candidate_keys: BTreeSet<_> = candidates.keys().copied().collect();
        let existing_indices: Vec<_> = rows
            .mappings
            .iter()
            .enumerate()
            .filter(|(_, mapping)| {
                mapping.artifact_symbol_fingerprint == symbol.fingerprint.as_bytes()
                    && mapping.source_kind == ArtifactAnalysisSourceKind::Unit
            })
            .map(|(index, _)| index)
            .collect();
        let existing_keys: BTreeSet<_> = existing_indices
            .iter()
            .map(|index| {
                let mapping = &rows.mappings[*index];
                (
                    mapping.source_fingerprint,
                    mapping.source_instance_fingerprint,
                    mapping.source_build_variant_fingerprint,
                )
            })
            .collect();
        let has_conflict = !existing_keys.is_empty() && existing_keys.is_disjoint(&candidate_keys);
        if has_conflict {
            for index in &existing_indices {
                rows.mappings[*index].evidence.has_conflict = true;
            }
        }
        for ((fingerprint, instance_fingerprint, build_variant_fingerprint), (unit, object_path)) in
            candidates
        {
            let existing = existing_indices.iter().copied().find(|index| {
                let mapping = &rows.mappings[*index];
                mapping.source_fingerprint == fingerprint
                    && mapping.source_instance_fingerprint == instance_fingerprint
                    && mapping.source_build_variant_fingerprint == build_variant_fingerprint
            });
            if let Some(index) = existing {
                let mapping = &mut rows.mappings[index];
                if !mapping.evidence.facts.iter().any(|fact| {
                    matches!(fact, MappingEvidenceFact::LinkerMap { object_path: existing } if existing == &object_path)
                }) {
                    mapping
                        .evidence
                        .facts
                        .push(MappingEvidenceFact::LinkerMap { object_path });
                }
                mapping.evidence.candidate_count =
                    mapping.evidence.candidate_count.max(candidate_count);
                mapping.evidence.has_conflict |= has_conflict;
            } else {
                rows.mappings.push(ArtifactAnalysisMapping {
                    schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                    artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                    source_kind: ArtifactAnalysisSourceKind::Unit,
                    source_fingerprint: unit.fingerprint,
                    source_instance_fingerprint: source_unit_instance_fingerprint(unit),
                    source_build_variant_fingerprint: unit.build_variant_fingerprint,
                    evidence: MappingEvidence::new(
                        linker_map_facts(unit, &symbol_name, object_path),
                        candidate_count,
                        has_conflict,
                    ),
                    attributed_bytes: None,
                    build_variant_fingerprint: artifact_variant,
                });
            }
        }
        rows.unmapped_symbols.retain(|unmapped| {
            unmapped.artifact_symbol_fingerprint != symbol.fingerprint.as_bytes()
        });
    }
}

pub(in crate::artifact) fn linker_map_facts(
    unit: &SourceUnitIdentity,
    artifact_symbol: &str,
    object_path: String,
) -> Vec<MappingEvidenceFact> {
    let source_symbol = unit.name.clone().unwrap_or_default();
    vec![
        MappingEvidenceFact::SymbolName {
            source_symbol,
            artifact_symbol: artifact_symbol.to_owned(),
        },
        MappingEvidenceFact::LinkerMap { object_path },
    ]
}

pub(in crate::artifact) fn linker_object_matches_source(
    object_path: &str,
    source_path: &str,
) -> bool {
    let object_path = object_path.replace('\\', "/");
    let source_path = source_path.replace('\\', "/");
    let Some(object_without_suffix) = object_path.strip_suffix(".o") else {
        return false;
    };
    object_without_suffix == source_path
        || object_without_suffix.ends_with(&format!("/{source_path}"))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "all correlation inputs stay at the source/artifact boundary"
)]
pub(in crate::artifact) fn correlate_debug_locations(
    artifact: &ArtifactIr,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    instantiations: &[SourceInstantiation],
    resolved_symbols: &[SourceResolvedSymbol],
    resolved_calls: &[SourceResolvedCall],
    artifact_variant: [u8; 16],
) -> CorrelationRows {
    let mut rows = CorrelationRows {
        clone_fragments: fragments.to_vec(),
        ..CorrelationRows::default()
    };
    for symbol in &artifact.symbols {
        let mut mapped = false;
        let mut seen_units = BTreeSet::new();
        let mut seen_fragments = BTreeSet::new();
        for frame in &symbol.inline_stack {
            let candidates: Vec<_> = units
                .iter()
                .filter(|unit| {
                    source_unit_matches(frame.source.as_str(), frame.line, scan_root, unit)
                })
                .collect();
            let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
            for unit in candidates {
                if !seen_units.insert((
                    source_unit_instance_fingerprint(unit),
                    unit.build_variant_fingerprint,
                )) {
                    continue;
                }
                rows.mappings.push(ArtifactAnalysisMapping {
                    schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                    artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                    source_kind: ArtifactAnalysisSourceKind::Unit,
                    source_fingerprint: unit.fingerprint,
                    source_instance_fingerprint: source_unit_instance_fingerprint(unit),
                    source_build_variant_fingerprint: unit.build_variant_fingerprint,
                    evidence: MappingEvidence::new(
                        vec![source_location_evidence(frame)],
                        candidate_count,
                        false,
                    ),
                    attributed_bytes: None,
                    build_variant_fingerprint: artifact_variant,
                });
                mapped = true;
            }
            let candidates: Vec<_> = fragments
                .iter()
                .filter(|fragment| {
                    source_fragment_matches(frame.source.as_str(), frame.line, scan_root, fragment)
                })
                .collect();
            let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
            for fragment in candidates {
                if !seen_fragments.insert((fragment.finding_id, fragment.build_variant_fingerprint))
                {
                    continue;
                }
                rows.mappings.push(ArtifactAnalysisMapping {
                    schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                    artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                    source_kind: ArtifactAnalysisSourceKind::Fragment,
                    source_fingerprint: fragment.fingerprint,
                    source_instance_fingerprint: fragment.finding_id,
                    source_build_variant_fingerprint: fragment.build_variant_fingerprint,
                    evidence: MappingEvidence::new(
                        vec![source_location_evidence(frame)],
                        candidate_count,
                        false,
                    ),
                    attributed_bytes: None,
                    build_variant_fingerprint: artifact_variant,
                });
                mapped = true;
            }
        }
        if !mapped {
            let generic_mappings = correlate_generic_origin(
                symbol,
                scan_root,
                units,
                fragments,
                instantiations,
                artifact_variant,
            );
            let name_mappings = correlate_symbol_name(
                symbol,
                scan_root,
                units,
                fragments,
                resolved_symbols,
                artifact_variant,
            );
            let fallback_mappings = combine_fallback_mappings(generic_mappings, name_mappings);
            mapped = !fallback_mappings.is_empty();
            rows.mappings.extend(fallback_mappings);
        }
        if !mapped {
            let reason = if symbol.inline_stack.is_empty() {
                ArtifactAnalysisUnmappedReason::DebugInfoMissing
            } else {
                ArtifactAnalysisUnmappedReason::OutsideSourceScope
            };
            rows.unmapped_symbols.push(ArtifactAnalysisUnmappedSymbol {
                artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                reason,
            });
        }
    }
    enrich_call_graph_evidence(
        artifact,
        scan_root,
        units,
        fragments,
        resolved_calls,
        &mut rows.mappings,
    );
    assign_unambiguous_fragment_bytes(artifact, &mut rows.mappings);
    // Artifact fingerprints deliberately describe stable symbol content rather
    // than a linker-local slot. A container can consequently expose the same
    // content identity through multiple symbol-table entries. The persistence
    // schema records one unmapped outcome per stable identity, so retain the
    // deterministic first reason instead of treating those entries as distinct
    // rows or leaking a SQLite uniqueness error.
    rows.unmapped_symbols.sort_by(|left, right| {
        left.artifact_symbol_fingerprint
            .cmp(&right.artifact_symbol_fingerprint)
            .then_with(|| {
                unmapped_reason_label(left.reason).cmp(unmapped_reason_label(right.reason))
            })
    });
    rows.unmapped_symbols
        .dedup_by_key(|unmapped| unmapped.artifact_symbol_fingerprint);
    let mapped_units = rows
        .mappings
        .iter()
        .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Unit)
        .map(|mapping| {
            (
                mapping.source_fingerprint,
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            )
        })
        .collect::<BTreeSet<_>>();
    rows.unmapped_sources = units
        .iter()
        .filter(|unit| {
            !mapped_units.contains(&(
                unit.fingerprint,
                source_unit_instance_fingerprint(unit),
                unit.build_variant_fingerprint,
            ))
        })
        .map(|unit| ArtifactAnalysisUnmappedSource {
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: unit.fingerprint,
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
        })
        .collect();
    let mapped_fragments = rows
        .mappings
        .iter()
        .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Fragment)
        .map(|mapping| {
            (
                mapping.source_fingerprint,
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            )
        })
        .collect::<BTreeSet<_>>();
    rows.unmapped_sources.extend(
        fragments
            .iter()
            .filter(|fragment| {
                !mapped_fragments.contains(&(
                    fragment.fingerprint,
                    fragment.finding_id,
                    fragment.build_variant_fingerprint,
                ))
            })
            .map(|fragment| ArtifactAnalysisUnmappedSource {
                source_kind: ArtifactAnalysisSourceKind::Fragment,
                source_fingerprint: fragment.fingerprint,
                source_instance_fingerprint: fragment.finding_id,
                source_build_variant_fingerprint: fragment.build_variant_fingerprint,
                reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
            }),
    );
    rows
}

/// Preserve the parser-established debug metadata family in correlation
/// evidence. A source path alone cannot distinguish PDB and DWARF provenance.
pub(in crate::artifact) fn source_location_evidence(
    frame: &codehelion_artifact::ArtifactInlineFrame,
) -> MappingEvidenceFact {
    match frame.evidence_kind {
        codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf => {
            MappingEvidenceFact::Dwarf {
                source_path: frame.source.clone(),
            }
        }
        codehelion_artifact::ArtifactSourceLocationEvidenceKind::Pdb => MappingEvidenceFact::Pdb {
            source_path: frame.source.clone(),
        },
    }
}

/// Derive an occurrence identity for one source unit without changing its
/// content-derived stable fingerprint. Equal source bodies can occur in more
/// than one file or declaration, and the `SQLite` correlation table retains each
/// occurrence independently. Source anchors are deliberately absent: a line
/// inserted above a declaration must not rename its persisted occurrence.
pub(in crate::artifact) fn source_unit_instance_fingerprint(unit: &SourceUnitIdentity) -> [u8; 16] {
    let mut bytes = Vec::new();
    for field in [
        unit.file_path.as_bytes(),
        unit.name.as_deref().unwrap_or_default().as_bytes(),
        unit.unit_kind.as_bytes(),
    ] {
        bytes.extend(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        bytes.extend(field);
    }
    bytes.extend(unit.fingerprint);
    bytes.extend(unit.occurrence_ordinal.to_le_bytes());
    bytes.extend(unit.build_variant_fingerprint);
    codehelion_artifact::ArtifactFingerprint::from_content("source-unit-instance-v2", &bytes)
        .as_bytes()
}

/// Derive a generic-definition origin identity without merging distinct
/// compiler-confirmed definitions that happen to share normalized source
/// content.
pub(in crate::artifact) fn generic_origin_fingerprint(
    source_fingerprint: [u8; 16],
    definition: &str,
) -> [u8; 16] {
    let mut bytes = Vec::with_capacity(source_fingerprint.len() + definition.len() + 1);
    bytes.extend(source_fingerprint);
    bytes.push(0);
    bytes.extend(definition.as_bytes());
    codehelion_artifact::ArtifactFingerprint::from_content("generic-origin-v1", &bytes).as_bytes()
}
