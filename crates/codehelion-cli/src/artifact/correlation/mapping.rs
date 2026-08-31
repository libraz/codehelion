//! Source-run loading, linker-map evidence, and debug-location correlation.

use super::matching::{
    InstantiationIndex, ResolvedSymbolIndex, SourceLocationIndex,
    assign_unambiguous_fragment_bytes, canonical_symbol_name, combine_fallback_mappings,
    correlate_generic_origin, correlate_symbol_name, enrich_call_graph_evidence,
    uniformly_separated,
};
use super::{
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSource, ArtifactAnalysisUnmappedSourceReason,
    ArtifactAnalysisUnmappedSymbol, ArtifactIr, BTreeMap, BTreeSet, BuildVariantEvidence, Context,
    CorrelationRows, FilePath, MAX_LINKER_MAP_BYTES, MappingEvidence, MappingEvidenceFact, Result,
    SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION, SourceFragmentIdentity, SourceInstantiation,
    SourceResolvedCall, SourceResolvedSymbol, SourceUnitIdentity, Store, bail, fs,
    source_kind_order, unmapped_reason_label,
};
use crate::artifact::SourceMapLocation;

/// Storage identity of one source-to-artifact correspondence.
///
/// The correlation table is unique over exactly these columns, so they are the
/// key every pass accumulates into.
type MappingKey = ([u8; 16], u8, [u8; 16], [u8; 16]);

/// The single accumulate-or-insert path for correlation mappings.
///
/// Artifact fingerprints describe stable symbol content rather than a
/// symbol-table slot, so content-identical functions — the duplication this
/// tool reports — reach the same key from separate entries. Every pass
/// therefore merges evidence into the existing row instead of appending a
/// second row that storage would reject, and both the lookup and the insert
/// stay logarithmic in the number of retained correspondences.
#[derive(Debug, Default)]
pub(in crate::artifact) struct MappingLedger {
    rows: Vec<ArtifactAnalysisMapping>,
    positions: BTreeMap<MappingKey, usize>,
}

impl MappingLedger {
    /// Start an empty ledger.
    pub(in crate::artifact) fn new() -> Self {
        Self::default()
    }

    /// Adopt already established rows, collapsing any equal keys among them.
    pub(in crate::artifact) fn from_rows(rows: Vec<ArtifactAnalysisMapping>) -> Self {
        let mut ledger = Self::new();
        ledger.extend(rows);
        ledger
    }

    /// Record one candidate correspondence under its storage identity.
    pub(in crate::artifact) fn insert(&mut self, mapping: ArtifactAnalysisMapping) {
        let key = mapping_key(&mapping);
        let Some(position) = self.positions.get(&key).copied() else {
            self.positions.insert(key, self.rows.len());
            self.rows.push(mapping);
            return;
        };
        let Some(existing) = self.rows.get_mut(position) else {
            return;
        };
        let variant_disagrees =
            existing.source_build_variant_fingerprint != mapping.source_build_variant_fingerprint;
        for fact in mapping.evidence.facts {
            if !existing.evidence.facts.contains(&fact) {
                existing.evidence.facts.push(fact);
            }
        }
        existing.evidence.candidate_count = existing
            .evidence
            .candidate_count
            .max(mapping.evidence.candidate_count);
        existing.evidence.has_conflict |= mapping.evidence.has_conflict || variant_disagrees;
        if existing.attributed_bytes.is_none() {
            existing.attributed_bytes = mapping.attributed_bytes;
        }
    }

    /// Record several candidates in order.
    pub(in crate::artifact) fn extend(
        &mut self,
        mappings: impl IntoIterator<Item = ArtifactAnalysisMapping>,
    ) {
        for mapping in mappings {
            self.insert(mapping);
        }
    }

    /// Positions of the retained correspondences for one symbol and source kind.
    pub(in crate::artifact) fn symbol_positions(
        &self,
        artifact_symbol_fingerprint: [u8; 16],
        source_kind: ArtifactAnalysisSourceKind,
    ) -> Vec<usize> {
        let kind = source_kind_order(source_kind);
        let low = (
            artifact_symbol_fingerprint,
            kind,
            [u8::MIN; 16],
            [u8::MIN; 16],
        );
        let high = (
            artifact_symbol_fingerprint,
            kind,
            [u8::MAX; 16],
            [u8::MAX; 16],
        );
        self.positions
            .range(low..=high)
            .map(|(_, position)| *position)
            .collect()
    }

    /// Read access to one retained correspondence.
    pub(in crate::artifact) fn row(&self, position: usize) -> Option<&ArtifactAnalysisMapping> {
        self.rows.get(position)
    }

    /// Mutable access to one retained correspondence.
    pub(in crate::artifact) fn row_mut(
        &mut self,
        position: usize,
    ) -> Option<&mut ArtifactAnalysisMapping> {
        self.rows.get_mut(position)
    }

    /// The retained correspondences, in the order they were first established.
    pub(in crate::artifact) fn rows_mut(&mut self) -> &mut [ArtifactAnalysisMapping] {
        &mut self.rows
    }

    /// Release the retained correspondences.
    pub(in crate::artifact) fn into_rows(self) -> Vec<ArtifactAnalysisMapping> {
        self.rows
    }
}

const fn mapping_key(mapping: &ArtifactAnalysisMapping) -> MappingKey {
    (
        mapping.artifact_symbol_fingerprint,
        source_kind_order(mapping.source_kind),
        mapping.source_fingerprint,
        mapping.source_instance_fingerprint,
    )
}

pub(in crate::artifact) fn correlate_source_run(
    artifact: &ArtifactIr,
    source_map_locations: &[SourceMapLocation],
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
    enrich_source_map_evidence(
        artifact,
        FilePath::new(&origin.root_path),
        &units,
        &fragments,
        source_map_locations,
        artifact_variant.fingerprint.as_bytes(),
        &mut rows,
    );
    enrich_linker_map_evidence(
        artifact,
        &units,
        linker_map,
        artifact_variant.fingerprint.as_bytes(),
        &mut rows,
    );
    // Every pass that can still establish a correspondence has run, so the
    // source side is split exactly once, from the final mapping set. Deciding
    // it earlier would report a unit that only source-map or linker-map
    // evidence reaches as both mapped and without artifact evidence.
    reconcile_unmapped_sources(&units, &fragments, &mut rows);
    Ok(rows)
}

/// Split the scan's source identities into mapped and unmapped, once.
///
/// Each discovered source occurrence belongs to exactly one side: it is either
/// named by a retained correspondence or recorded as reached by no artifact
/// evidence.
pub(in crate::artifact) fn reconcile_unmapped_sources(
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    rows: &mut CorrelationRows,
) {
    let mapped = rows
        .mappings
        .iter()
        .map(|mapping| {
            (
                source_kind_order(mapping.source_kind),
                mapping.source_fingerprint,
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            )
        })
        .collect::<BTreeSet<_>>();
    rows.unmapped_sources = units
        .iter()
        .map(|unit| ArtifactAnalysisUnmappedSource {
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: unit.fingerprint,
            source_instance_fingerprint: source_unit_instance_fingerprint(unit),
            source_build_variant_fingerprint: unit.build_variant_fingerprint,
            reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
        })
        .chain(
            fragments
                .iter()
                .map(|fragment| ArtifactAnalysisUnmappedSource {
                    source_kind: ArtifactAnalysisSourceKind::Fragment,
                    source_fingerprint: fragment.fingerprint,
                    source_instance_fingerprint: fragment.finding_id,
                    source_build_variant_fingerprint: fragment.build_variant_fingerprint,
                    reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
                }),
        )
        .filter(|source| {
            !mapped.contains(&(
                source_kind_order(source.source_kind),
                source.source_fingerprint,
                source.source_instance_fingerprint,
                source.source_build_variant_fingerprint,
            ))
        })
        .collect();
}

/// Add exact local source-map evidence for WASM symbols whose generated byte
/// ranges contain a resolved source-map token.
#[allow(
    clippy::too_many_arguments,
    reason = "the source-map join stays at one boundary"
)]
pub(in crate::artifact) fn enrich_source_map_evidence(
    artifact: &ArtifactIr,
    scan_root: &FilePath,
    units: &[SourceUnitIdentity],
    fragments: &[SourceFragmentIdentity],
    locations: &[SourceMapLocation],
    artifact_variant: [u8; 16],
    rows: &mut CorrelationRows,
) {
    let sources = SourceLocationIndex::new(scan_root, units, fragments);
    // Tokens are visited through one offset-ordered view, so a symbol reads the
    // tokens inside its own generated range instead of the whole map.
    let mut ordered_locations: Vec<usize> = (0..locations.len()).collect();
    ordered_locations.sort_by_key(|position| {
        (
            locations
                .get(*position)
                .map(|location| location.generated_offset),
            *position,
        )
    });
    let mut ledger = MappingLedger::from_rows(std::mem::take(&mut rows.mappings));
    for symbol in &artifact.symbols {
        let end = symbol.offset.saturating_add(symbol.size);
        let mut mapped = false;
        let first = ordered_locations.partition_point(|position| {
            locations
                .get(*position)
                .is_some_and(|location| location.generated_offset < symbol.offset)
        });
        for location in ordered_locations
            .get(first..)
            .unwrap_or_default()
            .iter()
            .filter_map(|position| locations.get(*position))
            .take_while(|location| location.generated_offset < end)
        {
            let units = sources.units_at(&location.source_url, location.source_line);
            let candidate_count = u32::try_from(units.len()).unwrap_or(u32::MAX);
            for unit in units {
                ledger.insert(source_map_mapping(
                    symbol.fingerprint.as_bytes(),
                    ArtifactAnalysisSourceKind::Unit,
                    unit.fingerprint,
                    source_unit_instance_fingerprint(unit),
                    unit.build_variant_fingerprint,
                    &location.source_url,
                    candidate_count,
                    artifact_variant,
                ));
                mapped = true;
            }
            let fragments = sources.fragments_at(&location.source_url, location.source_line);
            let candidate_count = u32::try_from(fragments.len()).unwrap_or(u32::MAX);
            for fragment in fragments {
                ledger.insert(source_map_mapping(
                    symbol.fingerprint.as_bytes(),
                    ArtifactAnalysisSourceKind::Fragment,
                    fragment.fingerprint,
                    fragment.finding_id,
                    fragment.build_variant_fingerprint,
                    &location.source_url,
                    candidate_count,
                    artifact_variant,
                ));
                mapped = true;
            }
        }
        if mapped {
            rows.unmapped_symbols.retain(|unmapped| {
                unmapped.artifact_symbol_fingerprint != symbol.fingerprint.as_bytes()
            });
        }
    }
    rows.mappings = ledger.into_rows();
}

#[allow(
    clippy::too_many_arguments,
    reason = "one mapping record has all identity dimensions"
)]
fn source_map_mapping(
    artifact_symbol_fingerprint: [u8; 16],
    source_kind: ArtifactAnalysisSourceKind,
    source_fingerprint: [u8; 16],
    source_instance_fingerprint: [u8; 16],
    source_build_variant_fingerprint: [u8; 16],
    source_url: &str,
    candidate_count: u32,
    artifact_variant: [u8; 16],
) -> ArtifactAnalysisMapping {
    ArtifactAnalysisMapping {
        schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
        artifact_symbol_fingerprint,
        source_kind,
        source_fingerprint,
        source_instance_fingerprint,
        source_build_variant_fingerprint,
        evidence: MappingEvidence::new(
            vec![MappingEvidenceFact::SourceMap {
                source_url: source_url.to_owned(),
            }],
            candidate_count,
            false,
        ),
        attributed_bytes: None,
        build_variant_fingerprint: artifact_variant,
    }
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
    // Both sides of this join are grouped by the name they are matched on, so
    // one symbol reads the entries and units that can name it rather than the
    // whole map and the whole scan.
    let mut entries_by_symbol: BTreeMap<String, Vec<&LinkerMapEntry>> = BTreeMap::new();
    for entry in entries {
        if let Some(name) = canonical_symbol_name(&entry.symbol) {
            entries_by_symbol.entry(name).or_default().push(entry);
        }
    }
    let mut units_by_name: BTreeMap<String, Vec<&SourceUnitIdentity>> = BTreeMap::new();
    for unit in units {
        if let Some(name) = unit.name.as_deref().and_then(canonical_symbol_name) {
            units_by_name.entry(name).or_default().push(unit);
        }
    }
    let mut ledger = MappingLedger::from_rows(std::mem::take(&mut rows.mappings));
    for symbol in &artifact.symbols {
        let Some(symbol_name) = symbol.name.as_deref().and_then(canonical_symbol_name) else {
            continue;
        };
        let named_units = units_by_name.get(&symbol_name);
        let mut candidates = BTreeMap::new();
        for entry in entries_by_symbol
            .get(&symbol_name)
            .into_iter()
            .flatten()
            .copied()
        {
            for unit in
                named_units.into_iter().flatten().copied().filter(|unit| {
                    linker_object_matches_source(&entry.object_path, &unit.file_path)
                })
            {
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
        let existing_positions = ledger.symbol_positions(
            symbol.fingerprint.as_bytes(),
            ArtifactAnalysisSourceKind::Unit,
        );
        let existing_keys: BTreeSet<_> = existing_positions
            .iter()
            .filter_map(|position| ledger.row(*position))
            .map(|mapping| {
                (
                    mapping.source_fingerprint,
                    mapping.source_instance_fingerprint,
                    mapping.source_build_variant_fingerprint,
                )
            })
            .collect();
        let has_conflict = !existing_keys.is_empty() && existing_keys.is_disjoint(&candidate_keys);
        if has_conflict {
            for position in &existing_positions {
                if let Some(mapping) = ledger.row_mut(*position) {
                    mapping.evidence.has_conflict = true;
                }
            }
        }
        for (candidate_key, (unit, object_path)) in candidates {
            // Name agreement is only new evidence where the linker map itself
            // established the correspondence. An already established mapping
            // gains the object-file placement alone.
            let facts = if existing_keys.contains(&candidate_key) {
                vec![MappingEvidenceFact::LinkerMap { object_path }]
            } else {
                linker_map_facts(unit, &symbol_name, object_path)
            };
            ledger.insert(ArtifactAnalysisMapping {
                schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
                artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
                source_kind: ArtifactAnalysisSourceKind::Unit,
                source_fingerprint: unit.fingerprint,
                source_instance_fingerprint: source_unit_instance_fingerprint(unit),
                source_build_variant_fingerprint: unit.build_variant_fingerprint,
                evidence: MappingEvidence::new(facts, candidate_count, has_conflict),
                attributed_bytes: None,
                build_variant_fingerprint: artifact_variant,
            });
        }
        rows.unmapped_symbols.retain(|unmapped| {
            unmapped.artifact_symbol_fingerprint != symbol.fingerprint.as_bytes()
        });
    }
    rows.mappings = ledger.into_rows();
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
    let object_path = uniformly_separated(object_path);
    let source_path = uniformly_separated(source_path);
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
    let sources = SourceLocationIndex::new(scan_root, units, fragments);
    let instantiation_index = InstantiationIndex::new(instantiations);
    let resolved_symbol_index = ResolvedSymbolIndex::new(resolved_symbols);
    let mut ledger = MappingLedger::new();
    for symbol in &artifact.symbols {
        let mut mapped = false;
        for frame in &symbol.inline_stack {
            let candidates = sources.units_at(frame.source.as_str(), frame.line);
            let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
            for unit in candidates {
                ledger.insert(ArtifactAnalysisMapping {
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
            let candidates = sources.fragments_at(frame.source.as_str(), frame.line);
            let candidate_count = u32::try_from(candidates.len()).unwrap_or(u32::MAX);
            for fragment in candidates {
                ledger.insert(ArtifactAnalysisMapping {
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
            let generic_mappings =
                correlate_generic_origin(symbol, &sources, &instantiation_index, artifact_variant);
            let name_mappings =
                correlate_symbol_name(symbol, &sources, &resolved_symbol_index, artifact_variant);
            let fallback_mappings = combine_fallback_mappings(generic_mappings, name_mappings);
            mapped = !fallback_mappings.is_empty();
            ledger.extend(fallback_mappings);
        }
        if !mapped {
            let reason = if artifact.capabilities.debug_info_unreadable {
                ArtifactAnalysisUnmappedReason::DebugInfoUnreadable
            } else if symbol.inline_stack.is_empty() {
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
    enrich_call_graph_evidence(artifact, &sources, resolved_calls, ledger.rows_mut());
    assign_unambiguous_fragment_bytes(artifact, scan_root, fragments, ledger.rows_mut());
    rows.mappings = ledger.into_rows();
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
    reconcile_unmapped_sources(units, fragments, &mut rows);
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
    codehelion_artifact::ArtifactFingerprint::from_content("source-unit-instance-v1", &bytes)
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
