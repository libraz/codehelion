//! Clone-group byte attribution and multiply-emitted source units.

use codehelion_store::BuildVariantFingerprint;
use codehelion_store::artifact::ArtifactAnalysisMappingConfidence;

use super::CorrelationRows;
use super::savings::{GroupSizeCategory, confidence_strength};
use crate::artifact::{
    ArtifactAnalysisMapping, ArtifactAnalysisSourceKind, ArtifactIr, BTreeMap, BTreeSet,
    EvidenceConfidence, MappingEvidenceFact, Serialize, SourceFragmentIdentity, fingerprint_hex,
};

/// Conservative observed bytes attributed to one source clone group.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct CloneGroupAttributionReport {
    /// Content-derived stable clone-group identity.
    pub(in crate::artifact) clone_group_fingerprint: String,
    /// Build variant that minted the group's member fingerprints.
    pub(in crate::artifact) source_build_variant_fingerprint: String,
    /// Members recorded for the group under this variant.
    pub(in crate::artifact) members: usize,
    /// Noncanonical members with at least one exact, unambiguous byte split.
    pub(in crate::artifact) attributed_noncanonical_members: usize,
    /// Observed bytes attributable to all noncanonical members, when every one
    /// of those members covers its whole artifact symbol.
    ///
    /// This is an attribution observation, not an estimated refactoring saving.
    /// A member whose share was divided across a symbol's source lines carries
    /// no observation of its own bytes, so one such member leaves this absent
    /// and moves the group's total to [`Self::estimated_duplicated_bytes`].
    pub(in crate::artifact) duplicated_bytes: Option<u64>,
    /// Bytes attributed to all noncanonical members when at least one share was
    /// divided by source lines.
    ///
    /// Line-proportional division is a construction, not a measurement: the
    /// lines say which fragment wrote a symbol, never how many of its bytes
    /// each line became. The value is therefore reported apart from the
    /// observed bucket and never added to it.
    pub(in crate::artifact) estimated_duplicated_bytes: Option<u64>,
    /// Distinct artifact symbols the group's noncanonical members were placed
    /// in, however the correspondence was established.
    ///
    /// A format that carries symbol names but no line frames — a WebAssembly
    /// name section is the common one — settles which symbol holds a member and
    /// nothing finer. Naming the symbols is what such a format can honestly
    /// say, so it is said instead of reporting the group as unreached.
    pub(in crate::artifact) containing_symbols: usize,
    /// Observed size of those symbols, summed once per symbol.
    ///
    /// This is the size of the code the members are part of, not the size of
    /// the members: a member sits inside its symbol and is usually smaller than
    /// it, and two members in one symbol are counted once. It is therefore an
    /// upper bound on what the group occupies and never a duplicated-byte
    /// total, which is why it stays out of [`Self::duplicated_bytes`] and
    /// [`Self::estimated_duplicated_bytes`] rather than filling in for either.
    pub(in crate::artifact) containing_symbol_bytes: Option<u64>,
    /// Source clone score kept separate from mapping and model confidence.
    pub(in crate::artifact) clone_confidence: f64,
}

impl CloneGroupAttributionReport {
    /// Every byte count this attribution states, with the value it holds.
    ///
    /// `None` is "the evidence for this is not there", never zero. Taken apart
    /// exhaustively, so a count added to [`GroupSizeCategory`] stops this
    /// compiling until it says where its number comes from, and every
    /// rendering takes its numbers from here.
    pub(in crate::artifact) fn stated(&self) -> Vec<(GroupSizeCategory, Option<u64>)> {
        GroupSizeCategory::all()
            .iter()
            .copied()
            .map(|category| {
                let bytes = match category {
                    GroupSizeCategory::Duplicated => self.duplicated_bytes,
                    GroupSizeCategory::EstimatedDuplicated => self.estimated_duplicated_bytes,
                    GroupSizeCategory::ContainingSymbols => self.containing_symbol_bytes,
                };
                (category, bytes)
            })
            .collect()
    }
}

/// One source unit the artifact emitted as more than one body.
///
/// Source copies and emitted bodies are different populations. A generic
/// written once is emitted once per instantiation, and a lambda passed to it
/// makes each instantiation a distinct type, so a single source copy can carry
/// a multiple of its own size in the artifact. Consolidating that one copy
/// removes no bodies at all, and the duplicate counts this tool is built on
/// cannot express the difference because there is only ever one copy to count.
///
/// This states the fan-out of the correspondence already established: how many
/// distinct artifact symbols one source unit was mapped to. It needs no
/// template analysis and no debug line information — only that the mapping
/// named a single source unit, so it is available wherever symbol names are.
///
/// Every number here is an observation about the artifact as it stands. None of
/// them is a saving: the bytes are what the artifact spends on this unit today,
/// and whether any of them can be removed is not a question this can answer.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct MultiplyEmittedUnitReport {
    /// Content-derived stable identity of the source unit, as `explain` takes.
    pub(in crate::artifact) source_fingerprint: String,
    /// Build variant that minted the source identity.
    pub(in crate::artifact) source_build_variant_fingerprint: String,
    /// Symbol spelling the correspondence matched on, kept as display evidence.
    pub(in crate::artifact) name: Option<String>,
    /// Distinct artifact symbols this one source unit was mapped to.
    pub(in crate::artifact) emitted_bodies: usize,
    /// Observed sizes of those symbols, summed.
    pub(in crate::artifact) observed_symbol_bytes: u64,
    /// Weakest grade among the mappings counted, so a reader can tell a
    /// name-only correspondence from a debug-located one.
    pub(in crate::artifact) mapping_confidence: EvidenceConfidence,
}

pub(in crate::artifact) fn clone_group_attributions(
    artifact: &ArtifactIr,
    rows: &CorrelationRows,
) -> Vec<CloneGroupAttributionReport> {
    attributed_groups(rows)
        .into_iter()
        .map(|group| {
            let (containing_symbols, containing_bytes) =
                resolved_symbols(artifact, &group.containing);
            CloneGroupAttributionReport {
                clone_group_fingerprint: group.clone_group_fingerprint,
                source_build_variant_fingerprint: group.source_build_variant_fingerprint,
                members: group.members,
                attributed_noncanonical_members: group.attributed_noncanonical_members,
                duplicated_bytes: group.duplicated_bytes,
                estimated_duplicated_bytes: group.estimated_duplicated_bytes,
                containing_symbols,
                containing_symbol_bytes: (containing_symbols > 0).then_some(containing_bytes),
                clone_confidence: group.clone_confidence,
            }
        })
        .collect()
}

/// How many of `fingerprints` this artifact holds, and how many bytes they are.
///
/// A mapping names a symbol of the artifact it was established against, so the
/// names are resolved here rather than counted where they were collected: a
/// report otherwise states a population that the artifact in hand may not
/// contain, and a size of zero would read as a measurement rather than as an
/// absence.
fn resolved_symbols(artifact: &ArtifactIr, fingerprints: &BTreeSet<[u8; 16]>) -> (usize, u64) {
    artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .fold((0, 0_u64), |(count, bytes), symbol| {
            (count + 1, bytes.saturating_add(symbol.size))
        })
}

/// One group's byte attribution, settled before the artifact is consulted.
///
/// The refactoring estimate is built from these numbers and from nothing the
/// artifact supplies. Keeping the two apart is what stops a symbol size from
/// reaching an estimate whose published model does not mention one; the symbols
/// a group sits in travel alongside as [`Self::containing`] and are resolved to
/// bytes only where they are reported as containment.
pub(super) struct AttributedGroup {
    pub(super) clone_group_fingerprint: String,
    pub(super) source_build_variant_fingerprint: String,
    pub(super) members: usize,
    pub(super) attributed_noncanonical_members: usize,
    pub(super) duplicated_bytes: Option<u64>,
    pub(super) estimated_duplicated_bytes: Option<u64>,
    pub(super) containing: BTreeSet<[u8; 16]>,
    pub(super) clone_confidence: f64,
}

pub(super) fn attributed_groups(rows: &CorrelationRows) -> Vec<AttributedGroup> {
    let mut groups: BTreeMap<_, Vec<&SourceFragmentIdentity>> = BTreeMap::new();
    for fragment in &rows.clone_fragments {
        groups
            .entry((
                fragment.clone_group_fingerprint,
                fragment.build_variant_fingerprint,
            ))
            .or_default()
            .push(fragment);
    }
    groups
        .into_iter()
        .map(|((group_fingerprint, source_variant), members)| {
            // The canonical member is the copy this accounting keeps rather
            // than counts as duplicated. The writer nominates it from content,
            // so reading its mark here attributes the same bytes to the same
            // occurrence however the scan reached the group's members.
            let noncanonical = members
                .iter()
                .filter(|member| !member.is_canonical)
                .map(|member| *member.finding_id.as_bytes())
                .collect::<BTreeSet<_>>();
            let mut bytes_by_member: BTreeMap<[u8; 16], MemberAttribution> = BTreeMap::new();
            // Where the members sit, which a format without line frames can
            // still settle, is collected beside the bytes they were charged,
            // which only line frames establish. A symbol enters this set once
            // however many members it holds.
            let mut containing: BTreeSet<[u8; 16]> = BTreeSet::new();
            for mapping in group_mappings(rows, source_variant, &noncanonical) {
                if places_one_source_unit(mapping) {
                    containing.insert(mapping.artifact_symbol_fingerprint);
                }
                if let Some(bytes) = mapping.attributed_bytes {
                    let member = bytes_by_member
                        .entry(mapping.source_instance_fingerprint)
                        .or_default();
                    member.total = member.total.saturating_add(bytes);
                    member.whole_symbol_only &= mapping
                        .evidence
                        .attribution_is_whole_symbol()
                        .unwrap_or(false);
                }
            }
            let attributed_noncanonical_members = bytes_by_member.len();
            let complete = attributed_noncanonical_members == noncanonical.len();
            let total = || {
                bytes_by_member
                    .values()
                    .map(|member| member.total)
                    .fold(0_u64, u64::saturating_add)
            };
            let whole_symbol_only = bytes_by_member
                .values()
                .all(|member| member.whole_symbol_only);
            AttributedGroup {
                clone_group_fingerprint: fingerprint_hex(*group_fingerprint.as_bytes()),
                source_build_variant_fingerprint: fingerprint_hex(source_variant.as_bytes()),
                members: members.len(),
                attributed_noncanonical_members,
                duplicated_bytes: (complete && whole_symbol_only).then(total),
                estimated_duplicated_bytes: (complete && !whole_symbol_only).then(total),
                containing,
                clone_confidence: members
                    .first()
                    .map_or(0.0, |member| member.clone_confidence),
            }
        })
        .collect()
}

/// Bytes attributed to one noncanonical member, with the evidence class that
/// established them.
#[derive(Debug)]
struct MemberAttribution {
    total: u64,
    whole_symbol_only: bool,
}

impl Default for MemberAttribution {
    fn default() -> Self {
        Self {
            total: 0,
            whole_symbol_only: true,
        }
    }
}

/// Whether this mapping settles the one source unit its symbol came from.
///
/// Both the fan-out count and the containment set answer "which source unit is
/// this symbol", so both need a mapping that named exactly one. An ambiguous
/// mapping named several and chose none: counting it would raise the fan-out of
/// every candidate at once, and would place a group in a symbol that may belong
/// to a different one. Evidence that no longer grades — an unknown schema, a
/// stale recipe version — settles nothing either.
fn places_one_source_unit(mapping: &ArtifactAnalysisMapping) -> bool {
    !matches!(
        mapping.evidence.confidence(),
        None | Some(ArtifactAnalysisMappingConfidence::Ambiguous)
    )
}

/// Source units the artifact emitted as more than one body, widest first.
///
/// The population is whole source units: a fragment is part of a unit, and the
/// question here is how many times a unit was emitted, not how many times a
/// stretch inside one was.
pub(in crate::artifact) fn multiply_emitted_units(
    artifact: &ArtifactIr,
    rows: &CorrelationRows,
) -> Vec<MultiplyEmittedUnitReport> {
    // Keyed by the source occurrence and the build that minted it: the two
    // digests name different things, and the key says which is which.
    let mut units: BTreeMap<([u8; 16], BuildVariantFingerprint), MultiplyEmittedUnit> =
        BTreeMap::new();
    for mapping in &rows.mappings {
        if mapping.source_kind != ArtifactAnalysisSourceKind::Unit
            || !places_one_source_unit(mapping)
        {
            continue;
        }
        let unit = units
            .entry((
                mapping.source_instance_fingerprint,
                mapping.source_build_variant_fingerprint,
            ))
            .or_insert_with(|| MultiplyEmittedUnit {
                content: mapping.source_fingerprint,
                name: None,
                symbols: BTreeSet::new(),
                weakest: None,
            });
        unit.symbols.insert(mapping.artifact_symbol_fingerprint);
        // The grade is folded in as each mapping is seen. Asking again per unit
        // afterwards would walk every mapping once for every unit reported,
        // which is the cost of the whole correlation multiplied by the number
        // of units a large artifact repeats.
        unit.weakest = weaker_of(unit.weakest, mapping_grade(mapping));
        if unit.name.is_none() {
            unit.name = mapping.evidence.facts.iter().find_map(|fact| match fact {
                MappingEvidenceFact::SymbolName { source_symbol, .. } => {
                    Some(source_symbol.clone())
                }
                _ => None,
            });
        }
    }
    let mut reports: Vec<_> = units
        .into_iter()
        .filter_map(|((_, variant), unit)| {
            let (emitted_bodies, observed_symbol_bytes) = resolved_symbols(artifact, &unit.symbols);
            // One body is a unit emitted the way reading the source suggests,
            // and there are as many of those as there are functions. Only a
            // unit the artifact repeated says something the source did not.
            (emitted_bodies > 1).then(|| MultiplyEmittedUnitReport {
                source_fingerprint: fingerprint_hex(unit.content),
                source_build_variant_fingerprint: fingerprint_hex(variant.as_bytes()),
                name: unit.name,
                emitted_bodies,
                observed_symbol_bytes,
                mapping_confidence: unit.weakest.unwrap_or(EvidenceConfidence::Unavailable),
            })
        })
        .collect();
    reports.sort_by(|left, right| {
        right
            .observed_symbol_bytes
            .cmp(&left.observed_symbol_bytes)
            .then_with(|| right.emitted_bodies.cmp(&left.emitted_bodies))
            .then_with(|| left.source_fingerprint.cmp(&right.source_fingerprint))
            .then_with(|| {
                left.source_build_variant_fingerprint
                    .cmp(&right.source_build_variant_fingerprint)
            })
    });
    reports
}

/// Symbols and display evidence accumulated for one source unit occurrence.
struct MultiplyEmittedUnit {
    content: [u8; 16],
    name: Option<String>,
    symbols: BTreeSet<[u8; 16]>,
    weakest: Option<EvidenceConfidence>,
}

/// The grade one mapping's evidence carries, on the scale a report states.
///
/// This is the same reading [`weakest_mapping_confidence`] takes over a whole
/// row set; it is spelled once here so a running fold and that function cannot
/// come to describe the same evidence differently.
pub(super) fn mapping_grade(mapping: &ArtifactAnalysisMapping) -> Option<EvidenceConfidence> {
    match mapping.evidence.confidence()? {
        ArtifactAnalysisMappingConfidence::Exact => Some(EvidenceConfidence::High),
        ArtifactAnalysisMappingConfidence::Strong => Some(EvidenceConfidence::Medium),
        ArtifactAnalysisMappingConfidence::Weak => Some(EvidenceConfidence::Low),
        ArtifactAnalysisMappingConfidence::Ambiguous => None,
    }
}

/// The lower of two grades, treating an absent one as nothing to lower to.
pub(super) const fn weaker_of(
    current: Option<EvidenceConfidence>,
    next: Option<EvidenceConfidence>,
) -> Option<EvidenceConfidence> {
    match (current, next) {
        (Some(current), Some(next)) => {
            if confidence_strength(current) <= confidence_strength(next) {
                Some(current)
            } else {
                Some(next)
            }
        }
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// Mappings whose attributed bytes belong to one group under one source variant.
pub(super) fn group_mappings<'rows>(
    rows: &'rows CorrelationRows,
    source_variant: BuildVariantFingerprint,
    noncanonical: &'rows BTreeSet<[u8; 16]>,
) -> impl Iterator<Item = &'rows ArtifactAnalysisMapping> + Clone {
    rows.mappings.iter().filter(move |mapping| {
        mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
            && mapping.source_build_variant_fingerprint == source_variant
            && noncanonical.contains(&mapping.source_instance_fingerprint)
    })
}

pub(in crate::artifact) fn observed_symbol_bytes_for(
    artifact: &ArtifactIr,
    fingerprints: &BTreeSet<[u8; 16]>,
) -> u64 {
    artifact
        .symbols
        .iter()
        .filter(|symbol| fingerprints.contains(&symbol.fingerprint.as_bytes()))
        .map(|symbol| symbol.size)
        .fold(0_u64, u64::saturating_add)
}
