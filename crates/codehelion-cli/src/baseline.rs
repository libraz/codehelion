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
//! Source locations are recorded alongside each entry, but only so a human
//! reading the file can tell what an entry refers to. Nothing matches on
//! them: line numbers move under edits that change nothing about the code.
//!
//! # Why the conditions are recorded with it
//!
//! A stable id means one thing under one build variant and detector version
//! set. A baseline made under different conditions would silently match
//! nothing — the worst possible failure for a suppression, since it looks
//! exactly like a suppression that worked. The file therefore records what it
//! was made under, and [`Baseline::compatibility`] states plainly when a run
//! does not match.
//!
//! Not every difference is fatal, and treating them alike would be its own
//! failure: a release that changed the order findings are read in would throw
//! away every frozen judgement in the project. Which differences matter is
//! decided by [`codehelion_core::compat`], and the ones that do can be carried
//! across rather than surrendered — see [`crate::migrate`].
//!
//! [`CloneGroupFingerprint`]: codehelion_core::stable_id::CloneGroupFingerprint

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use codehelion_core::compat::{self, Impact};
use codehelion_store::query::{RunOrigin, StoredGroup};
use serde::{Deserialize, Serialize};

use crate::migrate::Mapping;
use crate::report::DetectorVersion;

/// Version of the baseline file schema.
///
/// A change that stops an older file being readable must increment this. The
/// loader accepts every version up to this one and refuses only what was
/// written by a later build: refusing a file it could still read would make
/// the migration mechanism unreachable for exactly the users who need it,
/// since the file needing rewriting is by definition the older one.
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
    /// Rewrites this file has been through, oldest first. Absent from a file
    /// that has never been rewritten.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migrations: Vec<Migration>,
    /// Judgements a rewrite could not carry to the new identifiers, kept
    /// because a frozen finding is a decision somebody made and dropping it
    /// without saying so loses the decision along with the id. Nothing matches
    /// on them; they are here to be read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale: Vec<Entry>,
}

/// One rewrite of a baseline's identifiers onto a run made under changed
/// rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Migration {
    /// When it was applied, RFC 3339.
    pub at: String,
    /// The run the entries were written in terms of before.
    pub from_run: i64,
    /// The run they are written in terms of now.
    pub to_run: i64,
    /// Entries whose duplication the newer run found in the same places.
    pub carried: u64,
    /// Entries the newer run had nothing standing where they stood.
    pub stale: u64,
    /// The version differences that made the rewrite necessary, one line each.
    pub drift: Vec<String>,
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
    /// The stable finding id of each occurrence, in the order they were
    /// recorded. Kept so a later run can say which occurrences it knew about,
    /// not to match on.
    pub findings: Vec<String>,
    /// Where the canonical occurrence sat when the entry was written.
    /// Descriptive only — nothing matches on a location.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<Anchor>,
}

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
            migrations: Vec::new(),
            stale: Vec::new(),
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
        if baseline.schema_version > SCHEMA_VERSION {
            bail!(
                "baseline {} is schema version {}, and this build reads up to version {}",
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
    /// A detector version difference is weighed rather than counted. Only the
    /// components that decide what an id *is* stop the entries matching; a
    /// component that decides how findings are grouped leaves most of them
    /// intact, and one that decides only how they are displayed leaves all of
    /// them. Treating the three alike would discard a project's frozen
    /// judgements over a change that moved nothing.
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
        let recorded: Vec<(String, String)> = self
            .detector_versions
            .iter()
            .map(|entry| (entry.component.clone(), entry.version.clone()))
            .collect();
        let drift = compat::drift(&recorded, detectors);
        let named = |impact: Impact| -> Option<String> {
            let listed: Vec<String> = drift
                .iter()
                .filter(|entry| entry.impact == impact)
                .map(compat::Drift::describe)
                .collect();
            (!listed.is_empty()).then(|| listed.join(", "))
        };
        Compatibility {
            mismatch: named(Impact::Identifiers).map(|listed| {
                format!(
                    "recorded under detector versions that name findings differently ({listed}); \
                     `codehelion baseline migrate` rewrites it onto this run"
                )
            }),
            caveat: named(Impact::Grouping).map(|listed| {
                format!(
                    "grouped under different rules ({listed}), \
                     so an entry whose group gained or lost an occurrence reads as stale"
                )
            }),
        }
    }

    /// Rewrite the entries onto the identifiers a later run uses.
    ///
    /// Entries the mapping could not carry move to [`Self::stale`] rather than
    /// being dropped: the id is what went stale, and the judgement behind it
    /// is a decision somebody made about their code.
    ///
    /// The result describes the later run, and says so — the recorded variant,
    /// detector versions and originating run all move with the entries. A file
    /// that claimed to describe the run it no longer speaks the language of
    /// would fail the very check this exists to satisfy.
    #[must_use]
    pub fn migrated(
        &self,
        mapping: &Mapping,
        target: &RunOrigin,
        at: &str,
        drift: &[String],
    ) -> Self {
        let carried: BTreeMap<&str, &crate::migrate::Carried> = mapping
            .carried
            .iter()
            .map(|entry| (entry.from.as_str(), entry))
            .collect();
        let mut entries = Vec::with_capacity(self.entries.len());
        let mut stale = self.stale.clone();
        for entry in &self.entries {
            match carried.get(entry.group.as_str()) {
                Some(moved) => entries.push(Entry {
                    group: moved.to.clone(),
                    findings: moved.findings.clone(),
                    ..entry.clone()
                }),
                None => stale.push(entry.clone()),
            }
        }
        entries.sort_by(|a, b| a.group.cmp(&b.group));
        entries.dedup_by(|a, b| a.group == b.group);
        let mut migrations = self.migrations.clone();
        migrations.push(Migration {
            at: at.to_string(),
            from_run: self.from_run,
            to_run: target.id,
            carried: as_u64(entries.len()),
            stale: as_u64(stale.len() - self.stale.len()),
            drift: drift.to_vec(),
        });
        Self {
            schema_version: SCHEMA_VERSION,
            created_at: self.created_at.clone(),
            tool_version: target.tool_version.clone(),
            root: self.root.clone(),
            from_run: target.id,
            build_variant: Provenance {
                mode: target.analysis_mode.clone(),
                normalization_version: target.normalization_version,
                fingerprint: target.variant_fingerprint.clone(),
            },
            detector_versions: target
                .detector_versions
                .iter()
                .map(|(component, version)| DetectorVersion {
                    component: component.clone(),
                    version: version.clone(),
                })
                .collect(),
            entries,
            migrations,
            stale,
        }
    }
}

/// How well a baseline describes a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compatibility {
    /// Why none of the entries can match, when none can.
    pub mismatch: Option<String>,
    /// What differs without stopping the entries matching.
    pub caveat: Option<String>,
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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
            findings: group
                .members
                .iter()
                .map(|member| member.finding_hex.clone())
                .collect(),
            anchor: canonical.map(|member| Anchor {
                file: member.file_path.clone(),
                start_line: member.start_line.unwrap_or(0),
                end_line: member.end_line.unwrap_or(0),
                unit: member.unit_name.clone(),
            }),
        }
    }
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
            similarity: None,
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
        assert_eq!(baseline.entries[0].findings, vec!["f1", "f2"]);
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
    fn a_file_from_an_earlier_schema_still_loads() {
        // The file that needs rewriting is by definition the older one, so a
        // loader that refused everything but the current version would put the
        // migration mechanism out of reach of the users who need it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("baseline.json");
        let mut baseline = Baseline::from_run(&origin(), &[group("aa11")], "2026-07-27T01:00:00Z");
        baseline.schema_version = 1;
        baseline.write(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("migrations") && !text.contains("\"stale\""),
            "a file with nothing to say about rewrites says nothing: {text}"
        );

        let loaded = Baseline::load(&path).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.migrations.is_empty());
        assert!(loaded.stale.is_empty());
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

        let bumped = vec![("fp-schema".to_string(), "fp-schema-v2".to_string())];
        let other_detector = baseline
            .compatibility("abcdef0123456789", &bumped)
            .mismatch
            .expect("a moved fingerprint schema is a mismatch");
        assert!(other_detector.contains("fp-schema fp-schema-v1 -> fp-schema-v2"));
        assert!(other_detector.contains("baseline migrate"));
    }
}
