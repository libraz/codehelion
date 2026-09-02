//! Correlation fallback matching and attribution.

use super::{
    BTreeMap, SourceFragmentIdentity, SourceInstantiation, SourceResolvedSymbol, SourceUnitIdentity,
};
use std::path::Path as FilePath;

mod correlate;
mod name;
mod predicate;

pub(in crate::artifact) use correlate::{
    assign_unambiguous_fragment_bytes, combine_fallback_mappings, correlate_generic_origin,
    correlate_symbol_name, enrich_call_graph_evidence,
};
pub(in crate::artifact) use name::{
    canonical_symbol_name, normalized_clang_template_display_name,
    normalized_clang_template_owner_name, normalized_generic_instantiation_key,
    uniformly_separated,
};
pub(in crate::artifact) use predicate::{
    source_fragment_matches, source_generic_unit_matches, source_template_definition_contains_unit,
    source_unit_matches,
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
