//! Name stems: symbols whose names differ only in template arguments, closure
//! numbering or parameter lists, and how many bodies each stem accounts for.
//!
//! Symbols group under (stem, owner key, ownership), the owner being the one
//! already judged for the member symbol: the stem string is never judged
//! again, because the owner of a name depends on its original spelling.

use codehelion_artifact::ownership::{Ownership, PlatformUnderscoreLookup, SymbolOwner};
use codehelion_artifact::stem::{NameStem, name_stem};

use super::comparison::SymbolDelta;
use super::ownership::symbol_owners;
use crate::artifact::{ArtifactIr, BTreeMap, Serialize};

/// Stated beneath the stem section of an analysis.
const NAME_STEMS_FOLLOW_NAMES: &str = "name stems follow symbol names only, so overloads and same-named copies share a stem with template instantiations, and unnamed symbols belong to none";

/// What a stem row groups its bodies under: the stem, the owner key and the
/// ownership class of the member symbols.
type StemKey = (String, String, Ownership);

/// One stem emitted as several bodies in one artifact.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct NameStemReport {
    pub(in crate::artifact) stem: String,
    pub(in crate::artifact) parameterized: bool,
    pub(in crate::artifact) owner: String,
    pub(in crate::artifact) ownership: Ownership,
    pub(in crate::artifact) bodies: usize,
    pub(in crate::artifact) instances: usize,
    pub(in crate::artifact) size_bytes: u64,
    pub(in crate::artifact) instance_details: Vec<NameStemInstance>,
}

/// The bodies of one stem that share one spelling of their arguments.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct NameStemInstance {
    pub(in crate::artifact) instance: String,
    pub(in crate::artifact) bodies: usize,
    pub(in crate::artifact) size_bytes: u64,
}

/// Change in the bodies of one stem between two artifacts.
#[derive(Debug, Serialize)]
pub(in crate::artifact) struct StemDelta {
    pub(in crate::artifact) stem: String,
    pub(in crate::artifact) parameterized: bool,
    pub(in crate::artifact) owner: String,
    pub(in crate::artifact) ownership: Ownership,
    /// Symbols with this stem in the whole earlier artifact.
    pub(in crate::artifact) before_bodies: usize,
    /// Symbols with this stem in the whole later artifact.
    pub(in crate::artifact) after_bodies: usize,
    pub(in crate::artifact) delta_bytes: i128,
}

/// The stem of one symbol, in the context of the artifact it lies in.
pub(in crate::artifact) fn stem_of(
    platform: &PlatformUnderscoreLookup,
    symbol: &codehelion_artifact::ArtifactSymbol,
) -> Option<NameStem> {
    let name = symbol.name.as_deref()?;
    name_stem(name, platform.for_offset(symbol.offset))
}

/// The statement qualifying the stem rows, present only while there are rows.
pub(in crate::artifact) fn name_stem_assumptions(stems: &[NameStemReport]) -> Vec<String> {
    if stems.is_empty() {
        Vec::new()
    } else {
        vec![NAME_STEMS_FOLLOW_NAMES.to_owned()]
    }
}

/// The stems `artifact` emits as at least two bodies, whose symbols `owners`
/// labels in order.
pub(in crate::artifact) fn name_stems_of(
    artifact: &ArtifactIr,
    owners: &[SymbolOwner],
) -> Vec<NameStemReport> {
    #[derive(Default)]
    struct Group {
        parameterized: bool,
        bodies: usize,
        size_bytes: u64,
        instances: BTreeMap<String, (usize, u64)>,
    }
    let platform = PlatformUnderscoreLookup::new(artifact);
    let mut groups: BTreeMap<StemKey, Group> = BTreeMap::new();
    for (symbol, owner) in artifact.symbols.iter().zip(owners) {
        let Some(stem) = stem_of(&platform, symbol) else {
            continue;
        };
        let group = groups
            .entry((stem.stem, owner.key.clone(), owner.ownership))
            .or_default();
        group.parameterized |= stem.parameterized;
        group.bodies += 1;
        group.size_bytes += symbol.size;
        let instance = group.instances.entry(stem.instance).or_default();
        instance.0 += 1;
        instance.1 += symbol.size;
    }
    let mut rows: Vec<NameStemReport> = groups
        .into_iter()
        .filter(|(_, group)| group.bodies >= 2)
        .map(|((stem, owner, ownership), group)| {
            let mut instance_details: Vec<NameStemInstance> = group
                .instances
                .into_iter()
                .map(|(instance, (bodies, size_bytes))| NameStemInstance {
                    instance,
                    bodies,
                    size_bytes,
                })
                .collect();
            instance_details.sort_by(|left, right| {
                right
                    .size_bytes
                    .cmp(&left.size_bytes)
                    .then_with(|| left.instance.cmp(&right.instance))
            });
            NameStemReport {
                stem,
                parameterized: group.parameterized,
                owner,
                ownership,
                bodies: group.bodies,
                instances: instance_details.len(),
                size_bytes: group.size_bytes,
                instance_details,
            }
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| right.bodies.cmp(&left.bodies))
            .then_with(|| left.stem.cmp(&right.stem))
            .then_with(|| left.owner.cmp(&right.owner))
            .then_with(|| left.ownership.cmp(&right.ownership))
    });
    rows
}

/// How many symbols of `artifact` each stem accounts for, under the owner
/// labels a comparison gives its symbol deltas.
fn stem_bodies(artifact: &ArtifactIr) -> BTreeMap<StemKey, usize> {
    let platform = PlatformUnderscoreLookup::new(artifact);
    let mut counts = BTreeMap::new();
    for (symbol, owner) in artifact.symbols.iter().zip(symbol_owners(artifact)) {
        if let Some(stem) = stem_of(&platform, symbol) {
            *counts
                .entry((stem.stem, owner.key, owner.ownership))
                .or_default() += 1;
        }
    }
    counts
}

/// The stem rows of a comparison: stems whose symbol deltas number at least
/// two, or whose body count changed and reached two on either side.
pub(in crate::artifact) fn stem_deltas_of(
    deltas: &[SymbolDelta],
    before: &ArtifactIr,
    after: &ArtifactIr,
) -> Vec<StemDelta> {
    #[derive(Default)]
    struct Group {
        parameterized: bool,
        deltas: usize,
        delta_bytes: i128,
    }
    let mut groups: BTreeMap<StemKey, Group> = BTreeMap::new();
    for delta in deltas {
        let Some(stem) = &delta.stem else {
            continue;
        };
        let group = groups
            .entry((stem.stem.clone(), delta.owner.clone(), delta.ownership))
            .or_default();
        group.parameterized |= stem.parameterized;
        group.deltas += 1;
        group.delta_bytes += delta.size_delta_bytes;
    }
    let (before_bodies, after_bodies) = (stem_bodies(before), stem_bodies(after));
    let mut rows: Vec<StemDelta> = groups
        .into_iter()
        .filter_map(|(key, group)| {
            let before = before_bodies.get(&key).copied().unwrap_or(0);
            let after = after_bodies.get(&key).copied().unwrap_or(0);
            let listed = group.deltas >= 2 || (before != after && before.max(after) >= 2);
            listed.then_some(StemDelta {
                stem: key.0,
                parameterized: group.parameterized,
                owner: key.1,
                ownership: key.2,
                before_bodies: before,
                after_bodies: after,
                delta_bytes: group.delta_bytes,
            })
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .delta_bytes
            .unsigned_abs()
            .cmp(&left.delta_bytes.unsigned_abs())
            .then_with(|| left.stem.cmp(&right.stem))
            .then_with(|| left.owner.cmp(&right.owner))
            .then_with(|| left.ownership.cmp(&right.ownership))
    });
    rows
}
