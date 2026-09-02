//! Generic and macro origin aggregation over correlated artifact symbols.

use crate::artifact::{ArtifactIr, BTreeMap, BTreeSet, Serialize, metrics};

/// Observed artifact symbols attributed to one generic definition origin.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct GenericOriginReport {
    /// Compiler-confirmed definition spelling that distinguishes origins with
    /// otherwise identical source content.
    pub(in crate::artifact) definition: String,
    /// Content-derived source unit identity of the generic definition.
    pub(in crate::artifact) origin_fingerprint: String,
    /// Build variant that minted the origin identity.
    pub(in crate::artifact) origin_build_variant_fingerprint: String,
    /// Number of distinct compiler instantiation keys observed for this origin.
    pub(in crate::artifact) instantiations: usize,
    /// Number of translation units that independently observed the origin.
    pub(in crate::artifact) translation_units: usize,
    /// Number of distinct artifact symbols mapped to this origin.
    pub(in crate::artifact) artifact_symbols: usize,
    /// Sum of observed sizes of the distinct mapped artifact symbols.
    pub(in crate::artifact) observed_symbol_bytes: u64,
    /// Excess observed bytes in equal normalized instruction groups for this origin.
    ///
    /// This is a duplicate observation, not a claimed refactoring saving.
    pub(in crate::artifact) normalized_instruction_duplicated_bytes: u64,
    /// Sum of per-symbol retained sizes when the call graph supports them.
    ///
    /// Retained regions overlap, so this value must not be treated as a total.
    pub(in crate::artifact) retained_size_sum: Option<u64>,
    /// Observed artifact size split by exact compiler-reported specialization.
    pub(in crate::artifact) specializations: Vec<GenericSpecializationReport>,
}

/// Observed artifact symbols attributed to one declarative macro definition.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct MacroOriginReport {
    /// Content-derived identity of the source unit containing the macro body.
    pub(in crate::artifact) origin_fingerprint: String,
    /// Build variant that minted the origin identity.
    pub(in crate::artifact) origin_build_variant_fingerprint: String,
    /// Macro definition paths retained as auditable evidence.
    pub(in crate::artifact) definition_paths: Vec<String>,
    /// Number of distinct artifact symbols attributed to this macro body.
    pub(in crate::artifact) artifact_symbols: usize,
    /// Sum of observed sizes of the distinct mapped artifact symbols.
    pub(in crate::artifact) observed_symbol_bytes: u64,
}

/// One exact generic specialization contributing to an origin's artifact size.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct GenericSpecializationReport {
    /// Versioned compiler-reported instantiation key.
    pub(in crate::artifact) instantiation_key: String,
    /// Top-level type or value arguments parsed from the exact key.
    pub(in crate::artifact) type_arguments: Vec<String>,
    /// Number of distinct artifact symbols attributed to this specialization.
    pub(in crate::artifact) artifact_symbols: usize,
    /// Number of translation units that reported this specialization.
    pub(in crate::artifact) translation_units: usize,
    /// Sum of observed sizes of those symbols.
    pub(in crate::artifact) observed_symbol_bytes: u64,
}

/// Compiler observations accumulated for one exact specialization.
#[derive(Debug, Default)]
pub(in crate::artifact) struct GenericSpecializationAggregate {
    pub(in crate::artifact) symbols: BTreeSet<[u8; 16]>,
    pub(in crate::artifact) translation_units: BTreeSet<String>,
}

pub(in crate::artifact) fn generic_origin_metrics(
    artifact: &ArtifactIr,
    fingerprints: &BTreeSet<[u8; 16]>,
    retained_sizes: Option<&[metrics::RetainedSize]>,
) -> (u64, u64, Option<u64>) {
    let symbols: Vec<_> = artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .collect();
    let observed_symbol_bytes = symbols
        .iter()
        .map(|symbol| symbol.size)
        .fold(0_u64, u64::saturating_add);
    let mut normalized_groups: BTreeMap<(&str, &[u8]), Vec<u64>> = BTreeMap::new();
    for symbol in &symbols {
        if let Some(normalized) = &symbol.normalized {
            normalized_groups
                .entry((normalized.version.as_str(), normalized.bytes.as_slice()))
                .or_default()
                .push(symbol.size);
        }
    }
    let normalized_instruction_duplicated_bytes = normalized_groups
        .into_values()
        .filter(|sizes| sizes.len() > 1)
        .map(|sizes| {
            let total = sizes.iter().copied().fold(0_u64, u64::saturating_add);
            total.saturating_sub(sizes.into_iter().max().unwrap_or_default())
        })
        .fold(0_u64, u64::saturating_add);
    let retained_size_sum = retained_sizes.map(|sizes| {
        sizes
            .iter()
            .filter(|size| fingerprints.contains(&size.symbol.as_bytes()))
            .map(|size| size.retained_bytes)
            .fold(0_u64, u64::saturating_add)
    });
    (
        observed_symbol_bytes,
        normalized_instruction_duplicated_bytes,
        retained_size_sum,
    )
}

pub(in crate::artifact) fn generic_type_arguments(instantiation_key: &str) -> Vec<String> {
    let Some(start) = instantiation_key.find('<') else {
        return Vec::new();
    };
    let Some(arguments) = instantiation_key
        .strip_suffix('>')
        .and_then(|key| key.get(start + 1..))
    else {
        return Vec::new();
    };
    let mut depth = 0_u32;
    let mut arguments_out = Vec::new();
    let mut argument_start = 0;
    for (index, character) in arguments.char_indices() {
        match character {
            '<' => depth = depth.saturating_add(1),
            '>' => match depth.checked_sub(1) {
                Some(next) => depth = next,
                None => return Vec::new(),
            },
            ',' if depth == 0 => {
                let argument = arguments[argument_start..index].trim();
                if argument.is_empty() {
                    return Vec::new();
                }
                arguments_out.push(argument.to_owned());
                argument_start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Vec::new();
    }
    let argument = arguments[argument_start..].trim();
    if argument.is_empty() {
        return Vec::new();
    }
    arguments_out.push(argument.to_owned());
    arguments_out
}
