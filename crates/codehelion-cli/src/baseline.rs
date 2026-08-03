//! A recorded set of findings a project has decided not to act on yet.
//!
//! A baseline is the answer to arriving at an existing codebase: the tool
//! finds hundreds of duplications, none of them today's work, and a report
//! that is entirely history is a report nobody reads. Recording the current
//! result as a baseline makes the next scan report what came *after* it.
//!
//! # What it hides, and what it does not
//!
//! A baselined group is suppressed, not deleted: it is still detected, still
//! recorded in the audit database, and still listed under
//! `--show-suppressed`, carrying the baseline as the reason it was hidden.
//! This is the same treatment every other suppression gets, for the same
//! reason — a finding the tool stops mentioning is a finding nobody can
//! reconsider.
//!
//! # Why a group fingerprint is the key
//!
//! Entries are matched on [`CloneGroupFingerprint`], which is derived from
//! the *content* of the group's members. Two consequences are deliberate:
//!
//! - editing comments or whitespace does not move it, because neither
//!   survives tokenization, so a baseline does not evaporate on reformatting;
//! - adding a member whose content is new *does* move it, so a duplication
//!   that spreads to a new place stops being covered by a judgement made
//!   before it spread. Repeating content already in the group need not move
//!   the fingerprint, so an added occurrence is compared by its count.
//!
//! Source locations are recorded alongside each entry, but no entry is ever
//! *matched* on one: line numbers move under edits that change nothing about
//! the code, so a suppression keyed on a location would come and go with
//! reformatting.
//!
//! # Why the sites are recorded anyway
//!
//! Removing a duplication rearranges the code around it, and the groups that
//! come out of the rearrangement are new groups: a group fingerprint is
//! derived from its members' content, and a finding id from its group, so
//! nothing that identifies a finding survives the edit that made it. A run
//! that reported those groups as simply "new" would read as a regression to
//! the person who had just removed duplication.
//!
//! What does survive is the *site* — the file and the enclosing unit's name.
//! Each entry therefore records the site of every occurrence, and a scan
//! comparing itself against a baseline can say that a group appearing now
//! stands where an entry that has just gone stood. That claim is descriptive
//! and stated as such; it hides nothing and suppresses nothing.
//!
//! # Why the conditions are recorded with it
//!
//! A stable id means one thing under one build variant and detector version
//! set. A baseline made under different conditions would silently match
//! nothing — the worst possible failure for a suppression, since it looks
//! exactly like a suppression that worked. The file therefore records what it
//! was made under and requires an exact match. A file written under another
//! schema version is rejected rather than read, converted or reinterpreted.
//!
//! [`CloneGroupFingerprint`]: codehelion_core::stable_id::CloneGroupFingerprint

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_store::query::{RunOrigin, StoredGroup};
use serde::{Deserialize, Serialize};

use crate::report::DetectorVersion;
use crate::scan::display_path;

/// Version of the baseline file schema.
///
/// A file written under any other version is rejected rather than read with
/// the facts it does not carry guessed at. Recreating the baseline from the
/// current scan is the fix, and is cheap: a baseline is a record of a
/// judgement about the tree as it stands, not an archive.
pub const SCHEMA_VERSION: u32 = 2;

/// A baseline file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// Schema version of this file.
    pub schema_version: u32,
    /// When the baseline was recorded, RFC 3339.
    pub created_at: String,
    /// Tool version that recorded it.
    pub tool_version: String,
    /// Root the recorded run scanned.
    pub root: String,
    /// Frozen findings by the build variant that minted their stable ids.
    ///
    /// Semantic scans can record several independently compiled partitions
    /// in one invocation. Keeping their entries apart means a baseline can
    /// cover the whole invocation without pretending their identities are
    /// interchangeable.
    pub partitions: Vec<BaselinePartition>,
}

/// Frozen findings from one completed scan partition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselinePartition {
    /// Row id of the run the entries came from, for tracing them back.
    pub from_run: i64,
    /// The build variant the ids were computed under.
    pub build_variant: Provenance,
    /// The detection component versions they were computed under.
    pub detector_versions: Vec<DetectorVersion>,
    /// Minimum token window used to decide which clones could be detected.
    pub min_clone_tokens: i64,
    /// The frozen findings, ordered by group id.
    pub entries: Vec<Entry>,
}

/// The build variant a baseline's ids belong to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Analysis mode name.
    pub mode: String,
    /// Normalization version.
    pub normalization_version: i64,
    /// The variant's fingerprint, which is what a later run is compared on.
    pub fingerprint: String,
}

/// One frozen finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Hex clone-group fingerprint. This is the match key.
    pub group: String,
    /// The group's clone classification, for the reader.
    pub clone_type: String,
    /// How many occurrences the group had when it was frozen.
    pub instances: u64,
    /// Tokens the occurrences past the canonical one repeat.
    ///
    /// A measure of how much duplication the entry stands for, so that a scan
    /// reporting entries as gone can say how much went with them. Not a
    /// savings figure: nothing here claims an artifact would shrink by this
    /// much, or that unifying the occurrences is possible at all.
    pub duplicated_tokens: u64,
    /// Every occurrence, in the order they were recorded.
    pub occurrences: Vec<Occurrence>,
    /// Where the canonical occurrence sat when the entry was written.
    /// Descriptive only — nothing matches on a location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
}

/// One occurrence of a frozen finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Occurrence {
    /// The stable finding id, so a scan that still reports this group can say
    /// which occurrences it knew about. Not a match key.
    pub finding: String,
    /// Path relative to the scan root.
    pub file: String,
    /// Name of the enclosing unit, when it had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl Occurrence {
    /// The part of an occurrence that survives an edit to its content.
    fn site(&self) -> Site<'_> {
        (self.file.as_str(), self.unit.as_deref())
    }
}

/// A file and the unit inside it, which is what an occurrence keeps when the
/// code it holds is rewritten.
pub type Site<'a> = (&'a str, Option<&'a str>);

/// Where an occurrence sat, for a human reading the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Path relative to the scan root.
    pub file: String,
    /// 1-based first line.
    pub start_line: i64,
    /// 1-based last line.
    pub end_line: i64,
    /// Name of the enclosing unit, when it had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

impl Baseline {
    /// Freeze the reported findings of one recorded run.
    ///
    /// Groups hidden by an ordinary suppression rule are left out: a baseline
    /// records what was visible, and freezing one would keep hiding it after
    /// the rule that hid it was removed. A prior baseline is different: it is
    /// precisely the frozen set being refreshed, so those groups remain part
    /// of a newly created baseline.
    #[must_use]
    pub fn from_run(origin: &RunOrigin, groups: &[StoredGroup], created_at: &str) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            created_at: created_at.to_string(),
            tool_version: origin.tool_version.clone(),
            root: origin.root_path.clone(),
            partitions: vec![BaselinePartition::from_run(origin, groups)],
        }
    }

    /// Freeze every completed partition of one scan invocation.
    ///
    /// # Errors
    ///
    /// Returns an error when the caller mixes origins from different
    /// invocations, roots or tool versions, or when no completed partition
    /// was supplied.
    pub fn from_runs(runs: &[(RunOrigin, Vec<StoredGroup>)], created_at: &str) -> Result<Self> {
        let Some((first, _)) = runs.first() else {
            bail!("a baseline needs at least one completed scan partition");
        };
        if runs.iter().any(|(origin, _)| {
            origin.root_path != first.root_path
                || origin.tool_version != first.tool_version
                || origin.started_at != first.started_at
        }) {
            bail!(
                "a baseline cannot combine scan partitions from different invocations, roots or tool versions"
            );
        }
        let mut partitions: Vec<_> = runs
            .iter()
            .map(|(origin, groups)| BaselinePartition::from_run(origin, groups))
            .collect();
        partitions.sort_by(|left, right| {
            left.build_variant
                .fingerprint
                .cmp(&right.build_variant.fingerprint)
                .then_with(|| left.from_run.cmp(&right.from_run))
        });
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            created_at: created_at.to_string(),
            tool_version: first.tool_version.clone(),
            root: first.root_path.clone(),
            partitions,
        })
    }

    /// Read a baseline file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, is not valid JSON, or
    /// was written by a build whose schema this one does not know.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading baseline {}", path.display()))?;
        let baseline: Self = serde_json::from_str(&text)
            .with_context(|| format!("parsing baseline {}", path.display()))?;
        if baseline.schema_version != SCHEMA_VERSION {
            bail!(
                "baseline {} is schema version {}, but this build requires version {}",
                path.display(),
                baseline.schema_version,
                SCHEMA_VERSION
            );
        }
        Ok(baseline)
    }

    /// Write the baseline as pretty-printed JSON, with a trailing newline.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization or the write fails.
    pub fn write(&self, path: &Path) -> Result<()> {
        let mut text = serde_json::to_string_pretty(self).context("serializing the baseline")?;
        text.push('\n');
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
    }

    /// The group ids this baseline covers across all build variants.
    #[must_use]
    pub fn ids(&self) -> BTreeSet<&str> {
        self.partitions
            .iter()
            .flat_map(|partition| partition.entries.iter().map(|entry| entry.group.as_str()))
            .collect()
    }

    /// Partition recorded for `variant_fingerprint`, if this baseline has
    /// one. Callers reject a missing partition rather than silently applying
    /// entries minted for another build variant.
    #[must_use]
    pub fn partition(&self, variant_fingerprint: &str) -> Option<&BaselinePartition> {
        self.partitions
            .iter()
            .find(|partition| partition.build_variant.fingerprint == variant_fingerprint)
    }

    /// Drop stale entries from exactly one matching variant partition.
    ///
    /// A variant absent from the baseline remains absent: baseline update
    /// never adopts newly appeared findings or newly discovered partitions.
    #[must_use]
    pub fn pruned_partition(
        &self,
        variant_fingerprint: &str,
        present: &BTreeSet<String>,
    ) -> (Self, Vec<String>) {
        let mut kept = self.clone();
        let Some(partition) = kept
            .partitions
            .iter_mut()
            .find(|partition| partition.build_variant.fingerprint == variant_fingerprint)
        else {
            return (kept, Vec::new());
        };
        let dropped = partition.prune(present);
        (kept, dropped)
    }
}

impl BaselinePartition {
    /// Freeze the visible findings from one completed run.
    fn from_run(origin: &RunOrigin, groups: &[StoredGroup]) -> Self {
        let entries = groups
            .iter()
            .filter(|group| {
                group.suppress_reason.is_none()
                    && group
                        .suppressed_by
                        .as_ref()
                        .is_none_or(|suppression| suppression.scope == "baseline")
            })
            .map(Entry::from_group)
            .collect();
        Self {
            from_run: origin.id,
            build_variant: Provenance {
                mode: origin.analysis_mode.clone(),
                normalization_version: origin.normalization_version,
                fingerprint: origin.variant_fingerprint.clone(),
            },
            detector_versions: origin
                .detector_versions
                .iter()
                .filter(|(component, _)| is_baseline_detector_component(component))
                .map(|(component, version)| DetectorVersion {
                    component: component.clone(),
                    version: version.clone(),
                })
                .collect(),
            min_clone_tokens: origin.min_clone_tokens,
            entries,
        }
    }

    /// Drop entries absent from a later comparable run, returning their ids.
    fn prune(&mut self, present: &BTreeSet<String>) -> Vec<String> {
        let mut dropped = Vec::new();
        self.entries.retain(|entry| {
            let still_there = present.contains(&entry.group);
            if !still_there {
                dropped.push(entry.group.clone());
            }
            still_there
        });
        dropped
    }

    /// How well this partition describes a run under `detectors`.
    ///
    /// Detector versions must match exactly. Nothing here maps a superseded
    /// detector rule onto its replacement, so two runs scored under different
    /// rules are not compared.
    #[must_use]
    pub fn compatibility(
        &self,
        detectors: &[(String, String)],
        min_clone_tokens: i64,
    ) -> Compatibility {
        let mut recorded: Vec<(String, String)> = self
            .detector_versions
            .iter()
            .filter(|entry| is_baseline_detector_component(&entry.component))
            .map(|entry| (entry.component.clone(), entry.version.clone()))
            .collect();
        let mut current: Vec<(String, String)> = detectors
            .iter()
            .filter(|(component, _)| is_baseline_detector_component(component))
            .cloned()
            .collect();
        recorded.sort_unstable();
        current.sort_unstable();
        let mismatch = if self.min_clone_tokens == min_clone_tokens {
            (recorded != current).then_some(
                "recorded under different detector versions; recreate the baseline from this scan before using it"
                    .to_string(),
            )
        } else {
            Some(format!(
                "recorded with min-clone-tokens {}, but this scan uses {}; recreate the baseline from this scan before using it",
                self.min_clone_tokens, min_clone_tokens
            ))
        };
        Compatibility { mismatch }
    }
}

/// Whether a recorded component contributes to a finding's stable identity.
///
/// Ranking is presentation only. `compiler_ir` records the optional helper
/// answer schema; compiler evidence may adjust confidence but must not create
/// or remove a source finding, so an unavailable helper cannot invalidate a
/// baseline of the same source analysis.
fn is_baseline_detector_component(component: &str) -> bool {
    component != "ranking" && component != codehelion_store::compiler::IR_SCHEMA_COMPONENT
}

/// One group of the scan a baseline is being read against.
#[derive(Debug, Clone)]
pub struct ScanGroup<'a> {
    /// Hex clone-group fingerprint.
    pub group: &'a str,
    /// Occurrences the scan found in this group.
    pub instances: u64,
    /// Tokens this group repeats, on the same footing as
    /// [`Entry::duplicated_tokens`].
    pub duplicated_tokens: u64,
    /// Where each occurrence sits.
    pub sites: BTreeSet<Site<'a>>,
}

/// What a scan found relative to the baseline it was given.
///
/// Three states and nothing else: an entry the scan still reports, an entry it
/// no longer does, and a group it reports that the baseline never froze. The
/// third is the one that misleads without help, which is what
/// [`Appeared::derived_from`] is for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Delta {
    /// Entries the scan no longer reports, in baseline order.
    pub gone: Vec<Gone>,
    /// Groups the scan reports that the baseline did not freeze, in scan
    /// order.
    pub appeared: Vec<Appeared>,
    /// Frozen groups that now have more occurrences than the baseline froze.
    pub expanded: Vec<Expanded>,
    /// Entries the scan still reports.
    pub continuing: u64,
}

/// A frozen entry whose duplication the scan no longer reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gone {
    /// Hex group fingerprint of the entry.
    pub group: String,
    /// The entry's clone classification.
    pub clone_type: String,
    /// Tokens it repeated when it was frozen.
    pub duplicated_tokens: u64,
    /// Where its canonical occurrence sat.
    pub anchor: Option<Anchor>,
}

/// A group the scan reports that the baseline did not freeze.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appeared {
    /// Hex group fingerprint.
    pub group: String,
    /// Tokens it repeats.
    pub duplicated_tokens: u64,
    /// The entry that has gone from the same sites, when one has.
    pub derived_from: Option<Derivation>,
}

/// A frozen group whose duplication has spread to more occurrences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expanded {
    /// Hex group fingerprint.
    pub group: String,
    /// Occurrences added after this baseline was recorded.
    pub added_instances: u64,
    /// Repeated tokens added with those occurrences.
    pub added_tokens: u64,
}

/// The gone entry a group appears to have re-formed from.
///
/// Read it as "this stands where that stood", not as identity. Sites are
/// compared because nothing derived from content survives the edit that
/// removes a duplication; a group can therefore be named as the successor of
/// at most one entry, and only of one that has actually gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    /// Hex group fingerprint of the gone entry.
    pub group: String,
    /// How many of this group's occurrences sit at one of that entry's sites.
    pub shared_sites: u64,
}

impl BaselinePartition {
    /// Sort a scan's groups into what this partition froze and what it did not.
    ///
    /// `reported` is every group the scan found, whether or not a rule hid it:
    /// an entry is stale when the duplication is gone, not when some other
    /// rule got to it first.
    #[must_use]
    pub fn delta(&self, reported: &[ScanGroup<'_>]) -> Delta {
        let present: BTreeSet<&str> = reported.iter().map(|group| group.group).collect();
        let frozen: BTreeMap<&str, &Entry> = self
            .entries
            .iter()
            .map(|entry| (entry.group.as_str(), entry))
            .collect();

        let gone: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| !present.contains(entry.group.as_str()))
            .collect();
        let vacated: Vec<(&str, BTreeSet<Site<'_>>)> = gone
            .iter()
            .map(|entry| (entry.group.as_str(), entry.sites()))
            .collect();

        Delta {
            continuing: as_u64(self.entries.len() - gone.len()),
            gone: gone
                .iter()
                .map(|entry| Gone {
                    group: entry.group.clone(),
                    clone_type: entry.clone_type.clone(),
                    duplicated_tokens: entry.duplicated_tokens,
                    anchor: entry.anchor.clone(),
                })
                .collect(),
            appeared: reported
                .iter()
                .filter(|group| !frozen.contains_key(group.group))
                .map(|group| Appeared {
                    group: group.group.to_string(),
                    duplicated_tokens: group.duplicated_tokens,
                    derived_from: derivation(&group.sites, &vacated),
                })
                .collect(),
            expanded: reported
                .iter()
                .filter_map(|group| {
                    let entry = frozen.get(group.group)?;
                    (group.instances > entry.instances).then(|| Expanded {
                        group: group.group.to_string(),
                        added_instances: group.instances - entry.instances,
                        added_tokens: group
                            .duplicated_tokens
                            .saturating_sub(entry.duplicated_tokens),
                    })
                })
                .collect(),
        }
    }
}

/// The vacated entry sharing the most sites with `sites`, if any shares one.
///
/// Ties go to the lowest fingerprint so that the same scan always names the
/// same predecessor.
fn derivation(
    sites: &BTreeSet<Site<'_>>,
    vacated: &[(&str, BTreeSet<Site<'_>>)],
) -> Option<Derivation> {
    vacated
        .iter()
        .filter_map(|(group, left)| {
            let shared = sites.intersection(left).count();
            (shared > 0).then(|| Derivation {
                group: (*group).to_string(),
                shared_sites: as_u64(shared),
            })
        })
        .max_by(|a, b| {
            a.shared_sites
                .cmp(&b.shared_sites)
                .then_with(|| b.group.cmp(&a.group))
        })
}

/// A count as the width the report writes it in.
fn as_u64(count: usize) -> u64 {
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// A stored token count as the width the report writes it in.
fn tokens(count: i64) -> u64 {
    u64::try_from(count).unwrap_or(0)
}

/// How well a baseline describes a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compatibility {
    /// Why none of the entries can match, when none can.
    pub mismatch: Option<String>,
}

impl Entry {
    /// Freeze one stored group.
    fn from_group(group: &StoredGroup) -> Self {
        let canonical = group
            .members
            .iter()
            .find(|member| member.is_canonical)
            .or_else(|| group.members.first());
        Self {
            group: group.fingerprint_hex.clone(),
            clone_type: group.clone_type.clone(),
            instances: u64::try_from(group.members.len()).unwrap_or(u64::MAX),
            duplicated_tokens: duplicated_tokens(
                group
                    .members
                    .iter()
                    .map(|member| tokens(member.token_count)),
                canonical.map_or(0, |member| tokens(member.token_count)),
            ),
            occurrences: group
                .members
                .iter()
                .map(|member| Occurrence {
                    finding: member.finding_hex.clone(),
                    file: display_path(&member.file_path),
                    unit: member.unit_name.clone(),
                })
                .collect(),
            anchor: canonical.map(|member| Anchor {
                file: display_path(&member.file_path),
                start_line: member.start_line.unwrap_or(0),
                end_line: member.end_line.unwrap_or(0),
                unit: member.unit_name.clone(),
            }),
        }
    }

    /// The sites this entry's occurrences sat at.
    fn sites(&self) -> BTreeSet<Site<'_>> {
        self.occurrences.iter().map(Occurrence::site).collect()
    }
}

/// Tokens a group repeats: everything past the one copy a reader would keep.
///
/// Deliberately not "savings". It says how much text is written more than
/// once, which is a fact about the source, and stops there.
#[must_use]
pub fn duplicated_tokens(members: impl Iterator<Item = u64>, canonical: u64) -> u64 {
    members.sum::<u64>().saturating_sub(canonical)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
