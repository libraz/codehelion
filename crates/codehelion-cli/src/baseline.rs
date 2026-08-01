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
//!   before it spread.
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

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_store::query::{RunOrigin, StoredGroup};
use serde::{Deserialize, Serialize};

use crate::report::DetectorVersion;

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
    /// Row id of the run the entries came from, for tracing them back.
    pub from_run: i64,
    /// The build variant the ids were computed under.
    pub build_variant: Provenance,
    /// The detection component versions they were computed under.
    pub detector_versions: Vec<DetectorVersion>,
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
    /// Groups the run already hid are left out: a baseline records what was
    /// visible, and freezing an already-hidden group would keep hiding it
    /// after the rule that hid it was removed — a suppression nobody asked
    /// for, attributed to the wrong cause.
    #[must_use]
    pub fn from_run(origin: &RunOrigin, groups: &[StoredGroup], created_at: &str) -> Self {
        let entries = groups
            .iter()
            .filter(|group| group.suppressed_by.is_none() && group.suppress_reason.is_none())
            .map(Entry::from_group)
            .collect();
        Self {
            schema_version: SCHEMA_VERSION,
            created_at: created_at.to_string(),
            tool_version: origin.tool_version.clone(),
            root: origin.root_path.clone(),
            from_run: origin.id,
            build_variant: Provenance {
                mode: origin.analysis_mode.clone(),
                normalization_version: origin.normalization_version,
                fingerprint: origin.variant_fingerprint.clone(),
            },
            detector_versions: origin
                .detector_versions
                .iter()
                .map(|(component, version)| DetectorVersion {
                    component: component.clone(),
                    version: version.clone(),
                })
                .collect(),
            entries,
        }
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

    /// The group ids this baseline covers.
    #[must_use]
    pub fn ids(&self) -> BTreeSet<&str> {
        self.entries
            .iter()
            .map(|entry| entry.group.as_str())
            .collect()
    }

    /// Drop the entries whose duplication a later run no longer reports,
    /// returning the pruned baseline and the ids that went.
    ///
    /// Only removal happens here. A finding that appeared since the baseline
    /// was recorded is exactly what a baseline exists to surface, so taking it
    /// in silently would defeat the mechanism; adopting new findings is what
    /// re-recording the baseline is for.
    #[must_use]
    pub fn pruned(&self, present: &BTreeSet<String>) -> (Self, Vec<String>) {
        let mut kept = self.clone();
        let mut dropped = Vec::new();
        kept.entries.retain(|entry| {
            let still_there = present.contains(&entry.group);
            if !still_there {
                dropped.push(entry.group.clone());
            }
            still_there
        });
        (kept, dropped)
    }

    /// How well this baseline describes a run under `variant_fingerprint`
    /// with `detectors`.
    ///
    /// A build variant moves every id when it changes, so a baseline recorded
    /// under another one is not wrong about the code — it is talking about ids
    /// that no longer exist, and matching nothing is the expected outcome
    /// rather than a sign the duplication is gone.
    ///
    /// Detector versions must also match exactly. Nothing here maps a
    /// superseded detector rule onto its replacement, so two runs scored under
    /// different rules are not compared.
    #[must_use]
    pub fn compatibility(
        &self,
        variant_fingerprint: &str,
        detectors: &[(String, String)],
    ) -> Compatibility {
        if self.build_variant.fingerprint != variant_fingerprint {
            return Compatibility {
                mismatch: Some(format!(
                    "recorded under build variant {} in {} mode, and this run is variant {}",
                    short(&self.build_variant.fingerprint),
                    self.build_variant.mode,
                    short(variant_fingerprint),
                )),
                caveat: None,
            };
        }
        let mut recorded: Vec<(String, String)> = self
            .detector_versions
            .iter()
            .map(|entry| (entry.component.clone(), entry.version.clone()))
            .collect();
        let mut current = detectors.to_vec();
        recorded.sort_unstable();
        current.sort_unstable();
        Compatibility {
            mismatch: (recorded != current).then_some(
                "recorded under different detector versions; recreate the baseline from this scan before using it"
                    .to_string(),
            ),
            caveat: None,
        }
    }
}

/// One group of the scan a baseline is being read against.
#[derive(Debug, Clone)]
pub struct ScanGroup<'a> {
    /// Hex clone-group fingerprint.
    pub group: &'a str,
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

impl Baseline {
    /// Sort a scan's groups into what this baseline froze and what it did not.
    ///
    /// `reported` is every group the scan found, whether or not a rule hid it:
    /// an entry is stale when the duplication is gone, not when some other
    /// rule got to it first.
    #[must_use]
    pub fn delta(&self, reported: &[ScanGroup<'_>]) -> Delta {
        let present: BTreeSet<&str> = reported.iter().map(|group| group.group).collect();
        let frozen: BTreeSet<&str> = self.entries.iter().map(|e| e.group.as_str()).collect();

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
                .filter(|group| !frozen.contains(group.group))
                .map(|group| Appeared {
                    group: group.group.to_string(),
                    duplicated_tokens: group.duplicated_tokens,
                    derived_from: derivation(&group.sites, &vacated),
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
    /// What differs without stopping the entries matching.
    pub caveat: Option<String>,
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
                    file: member.file_path.clone(),
                    unit: member.unit_name.clone(),
                })
                .collect(),
            anchor: canonical.map(|member| Anchor {
                file: member.file_path.clone(),
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

/// An id abbreviated for a message, where the full 32 characters would drown
/// the sentence they sit in.
fn short(hex: &str) -> &str {
    hex.get(..12).unwrap_or(hex)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use codehelion_store::query::{StoredMember, StoredSuppressionRef};

    fn origin() -> RunOrigin {
        RunOrigin {
            id: 7,
            root_path: "/repo".to_string(),
            tool_version: "0.1.0".to_string(),
            analysis_mode: "structural".to_string(),
            finished_at: "2026-07-27T00:00:05Z".to_string(),
            variant_fingerprint: "abcdef0123456789".to_string(),
            normalization_version: 1,
            detector_versions: vec![("fp-schema".to_string(), "fp-schema-v1".to_string())],
        }
    }

    fn member(finding: &str, path: &str, canonical: bool) -> StoredMember {
        StoredMember {
            language: "rust".to_string(),
            content_hex: "c0".repeat(16),
            finding_hex: finding.to_string(),
            file_path: path.to_string(),
            start_line: Some(10),
            end_line: Some(20),
            token_count: 42,
            unit_name: Some("parse".to_string()),
            boilerplate: None,
            is_canonical: canonical,
        }
    }

    fn group(fingerprint: &str) -> StoredGroup {
        StoredGroup {
            fingerprint_hex: fingerprint.to_string(),
            clone_type: "type-2".to_string(),
            member_scope: "unit".to_string(),
            score: 0.9,
            entropy_bits: 4.0,
            suppress_reason: None,
            boilerplate: None,
            split_pair: false,
            test_code: false,
            width_family: false,
            statements: None,
            identifier_jaccard: None,
            has_loop: None,
            has_dynamic_allocation: None,
            call_count: None,
            similarity: None,
            semantic: None,
            suppressed_by: None,
            members: vec![
                member("f1", "src/a.rs", true),
                member("f2", "src/b.rs", false),
            ],
        }
    }

    #[test]
    fn freezing_a_run_records_what_it_reported_and_what_it_was() {
        let groups = vec![group("aa11"), group("bb22")];
        let baseline = Baseline::from_run(&origin(), &groups, "2026-07-27T01:00:00Z");

        assert_eq!(baseline.schema_version, SCHEMA_VERSION);
        assert_eq!(baseline.from_run, 7);
        assert_eq!(baseline.build_variant.fingerprint, "abcdef0123456789");
        assert_eq!(baseline.entries.len(), 2);
        assert_eq!(baseline.entries[0].group, "aa11");
        assert_eq!(baseline.entries[0].instances, 2);
        let sites: Vec<&str> = baseline.entries[0]
            .occurrences
            .iter()
            .map(|occurrence| occurrence.file.as_str())
            .collect();
        assert_eq!(sites, vec!["src/a.rs", "src/b.rs"]);
        let findings: Vec<&str> = baseline.entries[0]
            .occurrences
            .iter()
            .map(|occurrence| occurrence.finding.as_str())
            .collect();
        assert_eq!(findings, vec!["f1", "f2"]);
        // Two 42-token copies repeat everything past the one a reader keeps.
        assert_eq!(baseline.entries[0].duplicated_tokens, 42);
        let anchor = baseline.entries[0].anchor.as_ref().expect("an anchor");
        assert_eq!(anchor.file, "src/a.rs");
        assert_eq!(anchor.unit.as_deref(), Some("parse"));
    }

    #[test]
    fn a_group_the_run_already_hid_is_not_frozen_again() {
        let mut hidden = group("cc33");
        hidden.suppressed_by = Some(StoredSuppressionRef {
            scope: "path_glob".to_string(),
            pattern: "vendor/**".to_string(),
        });
        let mut noisy = group("dd44");
        noisy.suppress_reason = Some("low-entropy".to_string());

        let baseline = Baseline::from_run(
            &origin(),
            &[group("aa11"), hidden, noisy],
            "2026-07-27T01:00:00Z",
        );
        // Freezing a hidden group would outlive the rule that hid it.
        assert_eq!(baseline.ids(), BTreeSet::from(["aa11"]));
    }

    #[test]
    fn pruning_drops_what_is_gone_and_adopts_nothing_new() {
        let baseline = Baseline::from_run(
            &origin(),
            &[group("aa11"), group("bb22")],
            "2026-07-27T01:00:00Z",
        );
        let present: BTreeSet<String> = ["aa11".to_string(), "ee55".to_string()]
            .into_iter()
            .collect();

        let (pruned, dropped) = baseline.pruned(&present);
        assert_eq!(dropped, vec!["bb22".to_string()]);
        // `ee55` appeared after the baseline was recorded: that is precisely
        // what the baseline exists to show, so it is not taken in.
        assert_eq!(pruned.ids(), BTreeSet::from(["aa11"]));
    }

    /// A scan group standing at `sites`, with `tokens` repeated.
    fn scanned<'a>(group: &'a str, tokens: u64, sites: &[(&'a str, &'a str)]) -> ScanGroup<'a> {
        ScanGroup {
            group,
            duplicated_tokens: tokens,
            sites: sites
                .iter()
                .map(|(file, unit)| (*file, Some(*unit)))
                .collect(),
        }
    }

    #[test]
    fn a_delta_sorts_a_scan_into_gone_continuing_and_appeared() {
        let baseline = Baseline::from_run(
            &origin(),
            &[group("aa11"), group("bb22")],
            "2026-07-27T01:00:00Z",
        );

        let delta = baseline.delta(&[
            scanned("aa11", 40, &[("src/a.rs", "parse")]),
            scanned("ee55", 90, &[("src/z.rs", "other")]),
        ]);

        assert_eq!(delta.continuing, 1);
        assert_eq!(delta.gone.len(), 1);
        assert_eq!(delta.gone[0].group, "bb22");
        assert_eq!(delta.gone[0].duplicated_tokens, 42);
        assert_eq!(delta.appeared.len(), 1);
        assert_eq!(delta.appeared[0].group, "ee55");
        assert_eq!(delta.appeared[0].duplicated_tokens, 90);
        // Nothing vacated `src/z.rs`, so nothing is claimed about where it
        // came from.
        assert_eq!(delta.appeared[0].derived_from, None);
    }

    #[test]
    fn a_group_standing_where_a_gone_entry_stood_is_named_as_its_successor() {
        // Both entries were frozen over the same two units, which is what
        // happens when one duplication sits inside another.
        let baseline = Baseline::from_run(
            &origin(),
            &[group("aa11"), group("bb22")],
            "2026-07-27T01:00:00Z",
        );

        // `bb22` is gone; a group nobody has seen before now stands in the
        // same two units. Reporting it as plain "new" would read as a
        // regression to whoever had just removed `bb22`.
        let delta = baseline.delta(&[
            scanned("aa11", 42, &[("src/a.rs", "parse"), ("src/b.rs", "parse")]),
            scanned("ff66", 30, &[("src/a.rs", "parse"), ("src/b.rs", "parse")]),
        ]);

        let derived = delta.appeared[0]
            .derived_from
            .as_ref()
            .expect("a predecessor at the same sites");
        assert_eq!(derived.group, "bb22");
        assert_eq!(derived.shared_sites, 2);
    }

    #[test]
    fn an_entry_that_is_still_reported_is_not_offered_as_a_predecessor() {
        let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");

        // `aa11` still stands, so a second group over the same units is
        // duplication that was added, not duplication that moved.
        let delta = baseline.delta(&[
            scanned("aa11", 42, &[("src/a.rs", "parse")]),
            scanned("ff66", 30, &[("src/a.rs", "parse")]),
        ]);

        assert_eq!(delta.appeared.len(), 1);
        assert_eq!(delta.appeared[0].derived_from, None);
    }

    #[test]
    fn a_baseline_round_trips_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/baseline.json");
        let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");

        baseline.write(&path).unwrap();
        assert_eq!(Baseline::load(&path).unwrap(), baseline);

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'), "a text file ends with a newline");
        assert!(text.contains("\"group\": \"aa11\""), "readable by hand");
    }

    #[test]
    fn a_file_from_a_schema_this_build_does_not_read_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let mut baseline = Baseline::from_run(&origin(), &[], "2026-07-27T01:00:00Z");
        baseline.schema_version = SCHEMA_VERSION + 1;
        baseline.write(&path).unwrap();

        let err = Baseline::load(&path).expect_err("an unreadable schema version");
        assert!(format!("{err:#}").contains("schema version"));
    }

    #[test]
    fn a_baseline_says_when_it_describes_a_different_run() {
        let baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");
        let detectors = vec![("fp-schema".to_string(), "fp-schema-v1".to_string())];

        let fit = baseline.compatibility("abcdef0123456789", &detectors);
        assert_eq!(fit.mismatch, None);
        assert_eq!(fit.caveat, None);

        let other_variant = baseline
            .compatibility("999999999999", &detectors)
            .mismatch
            .expect("a different variant is a mismatch");
        assert!(other_variant.contains("build variant"));

        let bumped = vec![(
            "fp-schema".to_string(),
            "different-fingerprint-v1".to_string(),
        )];
        let other_detector = baseline
            .compatibility("abcdef0123456789", &bumped)
            .mismatch
            .expect("a moved fingerprint schema is a mismatch");
        assert!(other_detector.contains("different detector versions"));
        assert!(other_detector.contains("recreate the baseline"));
    }
}
