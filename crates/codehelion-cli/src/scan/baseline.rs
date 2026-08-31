//! Loading and applying accepted-finding baselines.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares baseline helpers across scan modes"
)]

use super::{
    BTreeMap, BaselineMode, BuildVariant, ContentHash, Path, Result, as_u64, bail, report, suppress,
};

/// A baseline a scan was told to apply.
pub(crate) struct ScanBaseline {
    /// The file as it was named on the command line.
    file: String,
    /// What the scan was told to do with the entries.
    mode: BaselineMode,
    /// The frozen entries for this run's build variant.
    entries: crate::baseline::BaselinePartition,
    /// The group ids it froze and the largest occurrence count each covers.
    covered: BTreeMap<String, u64>,
}

impl ScanBaseline {
    /// A digest of the frozen set, for recording which one a run was reported
    /// against.
    ///
    /// The file's path and the order its entries are written in change nothing
    /// about what is hidden. The covered count belongs in the digest: adding
    /// an occurrence changes whether an otherwise identical group is hidden.
    pub(crate) fn digest(&self) -> String {
        let mut joined = String::new();
        for (id, instances) in &self.covered {
            joined.push_str(id);
            joined.push(':');
            joined.push_str(&instances.to_string());
            joined.push('\n');
        }
        ContentHash::of(joined.as_bytes()).as_str().to_string()
    }
}

/// Load the baseline a scan was given and register it as a suppression rule.
///
/// Every scan partition must have a matching baseline partition and detector
/// contract. Continuing without one would make a request to hide known
/// findings look like a successful scan while covering a different result.
///
/// # Errors
///
/// Returns an error when the file cannot be read, is not a baseline this build
/// understands, has no matching partition, or has incompatible detector
/// versions. A named file that cannot be applied is a mistake worth stopping
/// for; silently scanning without it would report findings the user asked to
/// have hidden.
pub(crate) fn load_baseline(
    path: Option<&Path>,
    mode: BaselineMode,
    rules: &mut suppress::Rules,
    variant: &BuildVariant,
    detectors: &[(String, String)],
    min_clone_tokens: u32,
) -> Result<Option<ScanBaseline>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let baseline = crate::baseline::Baseline::load(path)?;
    let variant_fingerprint = variant.fingerprint();
    let Some(entries) = baseline.partition(&variant_fingerprint) else {
        bail!(
            "baseline {} does not describe this scan: it has no partition for build variant {}",
            path.display(),
            variant_fingerprint
        );
    };
    let fit = entries.compatibility(detectors, i64::from(min_clone_tokens));
    if let Some(reason) = fit.mismatch {
        bail!(
            "baseline {} does not describe this scan: {reason}",
            path.display()
        );
    }
    let covered: BTreeMap<String, u64> = entries
        .entries
        .iter()
        .map(|entry| (entry.group.clone(), entry.instances))
        .collect();
    let file = path.display().to_string();
    // Compare mode registers no rule: it is the mode for reading what moved,
    // and a report with the known half hidden cannot answer that.
    if mode == BaselineMode::Suppress {
        rules.add_baseline(&file, covered.clone());
    }
    Ok(Some(ScanBaseline {
        file,
        mode,
        entries: entries.clone(),
        covered,
    }))
}

/// Count this run against the baseline, and mark each group with where it
/// stands relative to it.
///
/// An entry counts as matched when the duplication it froze is still detected,
/// whichever rule ended up hiding it: the question a stale count answers is
/// whether the duplication is gone, not which reason won.
pub(crate) fn apply_baseline(
    baseline: &ScanBaseline,
    groups: &mut [report::Group],
) -> report::BaselineStatus {
    let scanned: Vec<crate::baseline::ScanGroup<'_>> = groups
        .iter()
        .map(|group| crate::baseline::ScanGroup {
            group: group.fingerprint.as_str(),
            instances: as_u64(group.members.len()),
            duplicated_tokens: report::duplicated_tokens(group),
            sites: group
                .members
                .iter()
                .map(|member| (member.file.as_str(), member.unit.as_deref()))
                .collect(),
        })
        .collect();
    let delta = baseline.entries.delta(&scanned);

    let derived: BTreeMap<&str, &crate::baseline::Appeared> = delta
        .appeared
        .iter()
        .map(|appeared| (appeared.group.as_str(), appeared))
        .collect();
    let expanded: BTreeMap<&str, &crate::baseline::Expanded> = delta
        .expanded
        .iter()
        .map(|entry| (entry.group.as_str(), entry))
        .collect();
    for group in groups.iter_mut() {
        let appeared = derived.get(group.fingerprint.as_str());
        let expansion = expanded.get(group.fingerprint.as_str());
        group.baseline = Some(report::GroupBaseline {
            state: if expansion.is_some() {
                report::GROUP_EXPANDED
            } else if appeared.is_some() {
                report::GROUP_NEW
            } else {
                report::GROUP_CONTINUING
            }
            .to_string(),
            added_instances: expansion.map(|entry| entry.added_instances),
            derived_from: appeared
                .and_then(|appeared| appeared.derived_from.as_ref())
                .map(|derivation| report::Derivation {
                    group: derivation.group.clone(),
                    shared_sites: derivation.shared_sites,
                }),
        });
    }

    report::BaselineStatus {
        file: baseline.file.clone(),
        mode: baseline.mode.name().to_string(),
        entries: as_u64(baseline.covered.len()),
        matched: delta.continuing,
        stale: as_u64(delta.gone.len()),
        appeared: as_u64(delta.appeared.len()),
        expanded: as_u64(delta.expanded.len()),
        expanded_instances: delta
            .expanded
            .iter()
            .map(|entry| entry.added_instances)
            .sum(),
        stale_tokens: delta.gone.iter().map(|entry| entry.duplicated_tokens).sum(),
        appeared_tokens: delta
            .appeared
            .iter()
            .map(|entry| entry.duplicated_tokens)
            .sum(),
        expanded_tokens: delta.expanded.iter().map(|entry| entry.added_tokens).sum(),
        gone: delta
            .gone
            .iter()
            .map(|entry| report::GoneGroup {
                group: entry.group.clone(),
                clone_type: entry.clone_type.clone(),
                duplicated_tokens: entry.duplicated_tokens,
                anchor: entry.anchor.as_ref().map(|anchor| report::GoneAnchor {
                    file: anchor.file.clone(),
                    start_line: anchor.start_line,
                    end_line: anchor.end_line,
                    unit: anchor.unit.clone(),
                }),
            })
            .collect(),
    }
}
