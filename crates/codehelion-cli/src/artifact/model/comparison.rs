//! Before/after artifact comparison models and per-symbol deltas.

use super::ArtifactContainment;
use super::assumption::{
    CONTAINER_WIDE_OBSERVED_BYTES, VERIFIED_SAVINGS_NEEDS_CONTROL, qualify_sizes,
};
use crate::artifact::{
    ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION, ArtifactIr, BTreeMap, BTreeSet, BinaryFormat,
    EstimatedRefactorSavingsBytes, ObservedSizeReductionBytes, Serialize, VerifiedSavingsBytes,
    metrics,
};

/// Versioned before/after result based only on parser-observed facts.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct ArtifactComparisonReport {
    pub(in crate::artifact) schema_version: &'static str,
    pub(in crate::artifact) before: ComparisonArtifact,
    pub(in crate::artifact) after: ComparisonArtifact,
    pub(in crate::artifact) containment: Option<ArtifactContainment>,
    pub(in crate::artifact) observed_size_reduction_bytes: ObservedSizeReductionBytes,
    pub(in crate::artifact) duplicated_code_delta_bytes: i128,
    pub(in crate::artifact) duplicated_data_delta_bytes: Option<i128>,
    /// Signed change in executable section bytes, so an observed difference
    /// can be attributed to code rather than to embedded data.
    pub(in crate::artifact) code_section_delta_bytes: i128,
    /// Signed change in data segment bytes, the other half of that question.
    pub(in crate::artifact) data_segment_delta_bytes: i128,
    pub(in crate::artifact) calibration: Option<CalibrationReport>,
    pub(in crate::artifact) symbol_changes: SymbolChanges,
    pub(in crate::artifact) symbol_deltas: Vec<SymbolDelta>,
    pub(in crate::artifact) duplicate_group_deltas: Vec<DuplicateGroupDelta>,
    pub(in crate::artifact) build_variant_warning: Option<String>,
    pub(in crate::artifact) assumptions: Vec<String>,
}

/// One controlled group-level measurement persisted from this comparison.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct CalibrationReport {
    pub(in crate::artifact) source_run: i64,
    pub(in crate::artifact) clone_group_fingerprint: String,
    /// Saved analysis whose stored estimate this measurement calibrated.
    ///
    /// Analysing one artifact twice leaves several analyses of one identity,
    /// so the report names the one the measurement was taken against instead
    /// of leaving the choice invisible.
    pub(in crate::artifact) artifact_analysis_id: i64,
    /// How many saved analyses held an estimate of that same identity.
    pub(in crate::artifact) matching_analyses: usize,
    /// Whether a measurement of this identity was already on file, in which
    /// case recording refreshed that row rather than failing the comparison.
    pub(in crate::artifact) already_recorded: bool,
    pub(in crate::artifact) estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes,
    pub(in crate::artifact) verified_savings_bytes: VerifiedSavingsBytes,
    pub(in crate::artifact) absolute_error_bytes: u64,
    pub(in crate::artifact) relative_error: Option<f64>,
}

#[derive(Debug, Serialize)]
pub(in crate::artifact) struct ComparisonArtifact {
    pub(in crate::artifact) path: String,
    pub(in crate::artifact) format: BinaryFormat,
    pub(in crate::artifact) fingerprint: String,
    pub(in crate::artifact) architecture: Option<String>,
    pub(in crate::artifact) skipped_architectures: Vec<String>,
    pub(in crate::artifact) build_variant: Option<ComparisonBuildVariant>,
    /// Executable section bytes, derived exactly as the single-artifact report
    /// derives them, so both surfaces answer "code or data?" the same way.
    pub(in crate::artifact) code_section_bytes: u64,
    /// Data segment bytes, derived the same way for the same reason.
    pub(in crate::artifact) data_segment_bytes: u64,
    pub(in crate::artifact) sizes: metrics::SizeClassification,
}

/// User-provided build-configuration evidence associated with one artifact.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct ComparisonBuildVariant {
    pub(in crate::artifact) manifest_path: String,
    pub(in crate::artifact) fingerprint: String,
}

/// Validated build-condition evidence that is safe to persist as a fingerprint.
#[derive(Debug, Clone)]
pub(in crate::artifact) struct BuildVariantEvidence {
    pub(in crate::artifact) manifest_path: String,
    pub(in crate::artifact) fingerprint: codehelion_artifact::ArtifactFingerprint,
}

impl BuildVariantEvidence {
    pub(in crate::artifact) fn for_report(&self) -> ComparisonBuildVariant {
        ComparisonBuildVariant {
            manifest_path: self.manifest_path.clone(),
            fingerprint: self.fingerprint.to_hex(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(in crate::artifact) struct SymbolChanges {
    pub(in crate::artifact) added: usize,
    pub(in crate::artifact) removed: usize,
    pub(in crate::artifact) modified_named_symbols: usize,
}

/// One changed parser-established symbol, ordered by absolute size delta.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct SymbolDelta {
    pub(in crate::artifact) kind: &'static str,
    pub(in crate::artifact) name: Option<String>,
    pub(in crate::artifact) fingerprint: String,
    pub(in crate::artifact) size_delta_bytes: i128,
}

/// What a comparison established about one symbol, as [`SymbolDelta::kind`]
/// spells it.
///
/// The first two name a symbol identity that occurs on one side only. The
/// other two name one symbol found on both sides whose bytes are not the same
/// bytes: identity is derived from the normalized instruction stream, which
/// drops immediates, so a build that only rewrote a constant or narrowed its
/// encoding arrives here rather than as an addition and a removal.
pub(in crate::artifact) mod symbol_change {
    /// A symbol identity present only in the later artifact.
    pub(in crate::artifact) const ADDED: &str = "added";
    /// A symbol identity present only in the earlier artifact.
    pub(in crate::artifact) const REMOVED: &str = "removed";
    /// One symbol found on both sides whose observed byte size changed.
    pub(in crate::artifact) const RESIZED: &str = "resized";
    /// One symbol found on both sides whose bytes changed while its observed
    /// size did not.
    pub(in crate::artifact) const MODIFIED: &str = "modified";
}

/// Whether this change names one symbol on both sides rather than one side.
///
/// A paired change is identified by the single fingerprint both sides share,
/// so it stays readable without a name; an unpaired one carries a different
/// fingerprint on each side and needs the name to be matched up by a reader.
pub(in crate::artifact) fn pairs_both_artifacts(kind: &str) -> bool {
    matches!(kind, symbol_change::RESIZED | symbol_change::MODIFIED)
}

/// The symbols one identity covers, as the earlier and the later artifact
/// carry them.
type SymbolsOfOneIdentity<'a> = (
    Vec<&'a codehelion_artifact::ArtifactSymbol>,
    Vec<&'a codehelion_artifact::ArtifactSymbol>,
);

/// Everything one comparison uses to tell two builds of one symbol apart.
///
/// [`ArtifactSymbol::fingerprint`] is the grouping key and stays so: it is the
/// identity the rest of the artifact pipeline routes calls, duplicates and
/// correlations through. It is derived from the normalized instruction stream,
/// which deliberately drops immediates, so it cannot answer whether the bytes
/// behind it moved. The body identity and the observed size answer that, and
/// they are held beside the key rather than folded into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolContent {
    /// Identity of the instruction bytes including their immediates, absent
    /// for a backend that does not decode operands.
    body: Option<codehelion_artifact::ArtifactFingerprint>,
    /// Observed byte size, which is evidence of a change on its own.
    size: u64,
}

impl SymbolContent {
    /// The content of one parser-established symbol.
    const fn of(symbol: &codehelion_artifact::ArtifactSymbol) -> Self {
        Self {
            body: symbol.body_fingerprint,
            size: symbol.size,
        }
    }
}

/// One equality-group change. `kind` identifies the independent equality
/// relation so a normalized match is never presented as an exact-byte match.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct DuplicateGroupDelta {
    pub(in crate::artifact) kind: &'static str,
    pub(in crate::artifact) fingerprint: String,
    pub(in crate::artifact) duplicated_bytes_delta: i128,
    pub(in crate::artifact) members_delta: i128,
}

impl ArtifactComparisonReport {
    pub(in crate::artifact) fn new(
        before_path: &std::path::Path,
        before: &ArtifactIr,
        before_variant: Option<ComparisonBuildVariant>,
        after_path: &std::path::Path,
        after: &ArtifactIr,
        after_variant: Option<ComparisonBuildVariant>,
    ) -> Self {
        let before_duplicates = metrics::find_duplicates(before);
        let before_data =
            metrics::find_duplicate_data(before, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        let mut before_sizes = metrics::CallGraph::from_ir(before)
            .classify_sizes_from_duplicates(&before_duplicates, &before_data);
        qualify_sizes(&mut before_sizes, &before.skipped_architectures);
        let after_duplicates = metrics::find_duplicates(after);
        let after_data =
            metrics::find_duplicate_data(after, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        let mut after_sizes = metrics::CallGraph::from_ir(after)
            .classify_sizes_from_duplicates(&after_duplicates, &after_data);
        qualify_sizes(&mut after_sizes, &after.skipped_architectures);
        let before_symbols = symbol_counts(before);
        let after_symbols = symbol_counts(after);
        let added = count_difference(&after_symbols, &before_symbols);
        let removed = count_difference(&before_symbols, &after_symbols);
        let modified_named_symbols = modified_named_symbols(before, after);
        let symbol_deltas = symbol_deltas(before, after);
        let duplicate_group_deltas = duplicate_group_deltas(
            &before_duplicates,
            &before_data,
            &after_duplicates,
            &after_data,
        );
        let mut assumptions = vec![
            "symbol identity is content-derived; an equal name with a changed fingerprint is reported as modified"
                .to_owned(),
            "symbol identity drops instruction immediates, so a symbol found on both sides whose bytes still differ is reported as resized or modified rather than as unchanged"
                .to_owned(),
            "observed_size_reduction_bytes is a measured artifact-byte difference, not a refactoring estimate"
                .to_owned(),
            VERIFIED_SAVINGS_NEEDS_CONTROL.to_owned(),
        ];
        if before.format != after.format {
            assumptions.push(
                "the artifact formats differ; size and symbol changes may reflect format changes"
                    .to_owned(),
            );
        }
        if !before.skipped_architectures.is_empty() || !after.skipped_architectures.is_empty() {
            assumptions.push(CONTAINER_WIDE_OBSERVED_BYTES.to_owned());
        }
        // The warning has a reported field of its own, and one condition
        // stated twice reads as two independent conditions.
        let build_variant_warning =
            build_variant_warning(before_variant.as_ref(), after_variant.as_ref());
        Self {
            schema_version: ARTIFACT_COMPARISON_REPORT_SCHEMA_VERSION,
            before: ComparisonArtifact {
                path: before_path.display().to_string(),
                format: before.format,
                fingerprint: before.fingerprint.to_hex(),
                architecture: before.architecture.clone(),
                skipped_architectures: before.skipped_architectures.clone(),
                build_variant: before_variant,
                code_section_bytes: code_section_bytes(before),
                data_segment_bytes: data_segment_bytes(before),
                sizes: before_sizes.clone(),
            },
            after: ComparisonArtifact {
                path: after_path.display().to_string(),
                format: after.format,
                fingerprint: after.fingerprint.to_hex(),
                architecture: after.architecture.clone(),
                skipped_architectures: after.skipped_architectures.clone(),
                build_variant: after_variant,
                code_section_bytes: code_section_bytes(after),
                data_segment_bytes: data_segment_bytes(after),
                sizes: after_sizes.clone(),
            },
            containment: None,
            observed_size_reduction_bytes: ObservedSizeReductionBytes(
                i128::from(before_sizes.observed_bytes) - i128::from(after_sizes.observed_bytes),
            ),
            duplicated_code_delta_bytes: difference(
                after_sizes.duplicated_bytes,
                before_sizes.duplicated_bytes,
            ),
            duplicated_data_delta_bytes: after_sizes
                .duplicated_data_bytes
                .zip(before_sizes.duplicated_data_bytes)
                .map(|(after, before)| difference(after, before)),
            code_section_delta_bytes: difference(
                code_section_bytes(after),
                code_section_bytes(before),
            ),
            data_segment_delta_bytes: difference(
                data_segment_bytes(after),
                data_segment_bytes(before),
            ),
            calibration: None,
            symbol_changes: SymbolChanges {
                added,
                removed,
                modified_named_symbols,
            },
            symbol_deltas,
            duplicate_group_deltas,
            build_variant_warning,
            assumptions,
        }
    }
}

pub(in crate::artifact) fn build_variant_warning(
    before: Option<&ComparisonBuildVariant>,
    after: Option<&ComparisonBuildVariant>,
) -> Option<String> {
    match (before, after) {
        (Some(before), Some(after)) if before.fingerprint != after.fingerprint => Some(
            "build variants differ; size and symbol changes may reflect build-condition changes"
                .to_owned(),
        ),
        (Some(_), None) | (None, Some(_)) => Some(
            "only one build variant was supplied; build-condition differences cannot be assessed"
                .to_owned(),
        ),
        (None, None) => Some(
            "no build variants were supplied; build-condition differences cannot be assessed"
                .to_owned(),
        ),
        (Some(_), Some(_)) => None,
    }
}

pub(in crate::artifact) fn duplicate_group_deltas(
    before_duplicates: &metrics::DuplicateReport,
    before_data: &[metrics::DuplicateGroup],
    after_duplicates: &metrics::DuplicateReport,
    after_data: &[metrics::DuplicateGroup],
) -> Vec<DuplicateGroupDelta> {
    let groups = |duplicates: &metrics::DuplicateReport, data: &[metrics::DuplicateGroup]| {
        [
            ("exact", duplicates.exact.as_slice()),
            ("normalized", duplicates.normalized.as_slice()),
            ("data", data),
        ]
        .into_iter()
        .flat_map(|(kind, groups)| {
            groups.iter().map(move |group| {
                (
                    (kind, group.fingerprint),
                    (group.duplicated_bytes, group.members.len()),
                )
            })
        })
        .collect::<BTreeMap<_, _>>()
    };
    let before_groups = groups(before_duplicates, before_data);
    let after_groups = groups(after_duplicates, after_data);
    let keys: BTreeSet<_> = before_groups
        .keys()
        .chain(after_groups.keys())
        .copied()
        .collect();
    keys.into_iter()
        .filter_map(|(kind, fingerprint)| {
            let (before_bytes, before_members) = before_groups
                .get(&(kind, fingerprint))
                .copied()
                .unwrap_or((0, 0));
            let (after_bytes, after_members) = after_groups
                .get(&(kind, fingerprint))
                .copied()
                .unwrap_or((0, 0));
            let duplicated_bytes_delta = difference(after_bytes, before_bytes);
            let members_delta =
                i128::try_from(after_members).ok()? - i128::try_from(before_members).ok()?;
            (duplicated_bytes_delta != 0 || members_delta != 0).then(|| DuplicateGroupDelta {
                kind,
                fingerprint: fingerprint.to_hex(),
                duplicated_bytes_delta,
                members_delta,
            })
        })
        .collect()
}

/// Every per-symbol difference between two artifacts, ordered by absolute size
/// delta.
///
/// Symbols are collected under the identity the rest of the pipeline uses, and
/// within one such group the members that carry the same bytes on both sides
/// are struck off against each other first. What is left is one symbol the two
/// builds disagree about: it is paired and reported as
/// [`symbol_change::RESIZED`] or [`symbol_change::MODIFIED`], rather than
/// silently cancelling because normalization erased what changed. Only members
/// with nothing to pair against remain an addition or a removal.
pub(in crate::artifact) fn symbol_deltas(
    before: &ArtifactIr,
    after: &ArtifactIr,
) -> Vec<SymbolDelta> {
    let mut groups: BTreeMap<codehelion_artifact::ArtifactFingerprint, SymbolsOfOneIdentity<'_>> =
        BTreeMap::new();
    for symbol in &before.symbols {
        groups.entry(symbol.fingerprint).or_default().0.push(symbol);
    }
    for symbol in &after.symbols {
        groups.entry(symbol.fingerprint).or_default().1.push(symbol);
    }
    let mut result = Vec::new();
    for (fingerprint, (before_members, after_members)) in groups {
        let fingerprint = fingerprint.to_hex();
        let (before_changed, after_changed) = unmatched_content(before_members, after_members);
        let mut before_changed = before_changed.into_iter();
        let mut after_changed = after_changed.into_iter();
        loop {
            match (before_changed.next(), after_changed.next()) {
                (Some(earlier), Some(later)) => result.push(SymbolDelta {
                    kind: if earlier.size == later.size {
                        symbol_change::MODIFIED
                    } else {
                        symbol_change::RESIZED
                    },
                    // Both sides share one identity, so either name is the
                    // symbol's; the later artifact is what the report is about.
                    name: later.name.clone().or_else(|| earlier.name.clone()),
                    fingerprint: fingerprint.clone(),
                    size_delta_bytes: difference(later.size, earlier.size),
                }),
                (Some(earlier), None) => result.push(SymbolDelta {
                    kind: symbol_change::REMOVED,
                    name: earlier.name.clone(),
                    fingerprint: fingerprint.clone(),
                    size_delta_bytes: -i128::from(earlier.size),
                }),
                (None, Some(later)) => result.push(SymbolDelta {
                    kind: symbol_change::ADDED,
                    name: later.name.clone(),
                    fingerprint: fingerprint.clone(),
                    size_delta_bytes: i128::from(later.size),
                }),
                (None, None) => break,
            }
        }
    }
    result.sort_by(|left, right| {
        right
            .size_delta_bytes
            .unsigned_abs()
            .cmp(&left.size_delta_bytes.unsigned_abs())
            .then_with(|| left.fingerprint.cmp(&right.fingerprint))
    });
    result
}

/// Strike off the members of one identity group that carry the same bytes on
/// both sides, and return what each side has left.
///
/// Byte-equal members are the ones a comparison has nothing to say about, so
/// cancelling them first is what keeps a symbol that did change from being
/// paired against an unrelated twin. Both remainders come back in a
/// content-then-offset order, so the pairing that follows does not depend on
/// the order the symbols happened to be laid out in.
fn unmatched_content<'a>(
    before: Vec<&'a codehelion_artifact::ArtifactSymbol>,
    after: Vec<&'a codehelion_artifact::ArtifactSymbol>,
) -> SymbolsOfOneIdentity<'a> {
    let mut unmatched: BTreeMap<SymbolContent, usize> = BTreeMap::new();
    for symbol in &before {
        *unmatched.entry(SymbolContent::of(symbol)).or_default() += 1;
    }
    let mut remaining_after = Vec::new();
    for symbol in after {
        match unmatched.get_mut(&SymbolContent::of(symbol)) {
            Some(count) if *count > 0 => *count -= 1,
            _ => remaining_after.push(symbol),
        }
    }
    let mut remaining_before = Vec::new();
    for symbol in before {
        if let Some(count) = unmatched.get_mut(&SymbolContent::of(symbol))
            && *count > 0
        {
            *count -= 1;
            remaining_before.push(symbol);
        }
    }
    let order = |symbol: &&codehelion_artifact::ArtifactSymbol| (symbol.size, symbol.offset);
    remaining_before.sort_by_key(order);
    remaining_after.sort_by_key(order);
    (remaining_before, remaining_after)
}

pub(in crate::artifact) fn symbol_counts(
    artifact: &ArtifactIr,
) -> BTreeMap<codehelion_artifact::ArtifactFingerprint, usize> {
    let mut counts = BTreeMap::new();
    for symbol in &artifact.symbols {
        *counts.entry(symbol.fingerprint).or_default() += 1;
    }
    counts
}

pub(in crate::artifact) fn count_difference(
    left: &BTreeMap<codehelion_artifact::ArtifactFingerprint, usize>,
    right: &BTreeMap<codehelion_artifact::ArtifactFingerprint, usize>,
) -> usize {
    left.iter()
        .map(|(fingerprint, count)| count.saturating_sub(*right.get(fingerprint).unwrap_or(&0)))
        .sum()
}

/// How many named symbols one artifact carries differently from the other.
///
/// A name is counted when it belongs to exactly one symbol on each side and
/// those two symbols are not the same symbol. That is a question about the
/// grouping identity and about the bytes behind it: two builds of one function
/// whose opcode sequence did not move share the identity, so the body identity
/// and the observed size are what separate them, exactly as they do in
/// [`symbol_deltas`].
pub(in crate::artifact) fn modified_named_symbols(
    before: &ArtifactIr,
    after: &ArtifactIr,
) -> usize {
    let names = |artifact: &ArtifactIr| {
        let mut result: BTreeMap<
            String,
            BTreeSet<(codehelion_artifact::ArtifactFingerprint, SymbolContent)>,
        > = BTreeMap::new();
        for symbol in &artifact.symbols {
            if let Some(name) = symbol.name.as_deref() {
                result
                    .entry(name.to_owned())
                    .or_default()
                    .insert((symbol.fingerprint, SymbolContent::of(symbol)));
            }
        }
        result
    };
    let before_names = names(before);
    let after_names = names(after);
    before_names
        .iter()
        .filter(|(name, identities)| {
            identities.len() == 1
                && after_names.get(*name).is_some_and(|after_identities| {
                    after_identities.len() == 1 && after_identities != *identities
                })
        })
        .count()
}

pub(in crate::artifact) fn difference(after: u64, before: u64) -> i128 {
    i128::from(after) - i128::from(before)
}

/// Executable section bytes observed in one artifact.
pub(in crate::artifact) fn code_section_bytes(artifact: &ArtifactIr) -> u64 {
    artifact
        .sections
        .iter()
        .filter(|section| section.executable)
        .map(|section| section.size)
        .sum()
}

/// Data segment bytes observed in one artifact.
pub(in crate::artifact) fn data_segment_bytes(artifact: &ArtifactIr) -> u64 {
    artifact
        .data_segments
        .iter()
        .map(|segment| segment.bytes.len() as u64)
        .sum()
}
