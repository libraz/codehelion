//! The read path: every SQL query the CLI needs, as functions.
//!
//! SQL strings live here and nowhere else, so the CLI layer talks in domain
//! types. Result ordering is deterministic everywhere: groups order by their
//! fingerprint bytes (priority ordering joins in with the priority stage),
//! members in the order the run recorded them — the same database always
//! yields the same output.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::features::FeatureKind;
use codehelion_core::lineage::{Anchor, GroupSnapshot, MemberSnapshot};
use codehelion_core::stable_id::{CloneGroupFingerprint, FragmentFingerprint, GroupLineageId};
use rusqlite::{OptionalExtension, params};

use crate::snapshot::{FunnelDropRow, FunnelStageRow, SummaryRow, UnparsedRow, UnusedRuleRow};
use crate::{Store, StoreError};

/// A recorded run and the tree it read, by path relative to the scan root.
///
/// The hashes are hex as stored; turning them back into content fingerprints
/// is the caller's, because this layer does not depend on how they were made.
pub type PreviousTree = (i64, BTreeMap<PathBuf, String>);

/// Summary of one recorded scan run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    /// Row id of the run.
    pub id: i64,
    /// Scanned root path.
    pub root_path: String,
    /// Tool version that wrote the run.
    pub tool_version: String,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// RFC 3339 start time.
    pub started_at: String,
    /// RFC 3339 finish time, if the run completed.
    pub finished_at: Option<String>,
    /// Number of clone groups recorded for the run.
    pub group_count: i64,
}

/// Where a recorded run came from: enough of its identity to say whether a
/// judgement made about its results still describes a later run.
///
/// A stable id is only meaningful under the conditions it was computed in, so
/// an artefact derived from a run (a baseline, an exported diff) has to carry
/// them. The build variant is the decisive one — it folds mode, languages and
/// normalization version into one fingerprint — but the detector versions are
/// recorded beside it, because a fingerprint schema change moves every id
/// without the variant noticing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOrigin {
    /// Row id of the run.
    pub id: i64,
    /// Scanned root path.
    pub root_path: String,
    /// Tool version that wrote the run.
    pub tool_version: String,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// RFC 3339 finish time.
    pub finished_at: String,
    /// The build variant's fingerprint.
    pub variant_fingerprint: String,
    /// Normalization version the variant was built under.
    pub normalization_version: i64,
    /// Every recorded `(component, version)` pair, ordered by component.
    pub detector_versions: Vec<(String, String)>,
}

/// What a recorded run was told to do, as opposed to what it found.
///
/// Everything here is an input: the tree, the settings, the release. Two runs
/// that agree on all of it and read the same bytes have the same answer, which
/// is what lets one of them be reported again instead of recomputed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    /// Row id of the run.
    pub id: i64,
    /// Scanned root path.
    pub root_path: String,
    /// Tool version that wrote the run.
    pub tool_version: String,
    /// Hash of the effective configuration it ran under.
    pub config_hash: String,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// RFC 3339 start time.
    pub started_at: String,
    /// RFC 3339 finish time.
    pub finished_at: String,
    /// The shortest clone the run would report. `None` for a run recorded
    /// before runs stored the floor they reported under.
    pub min_clone_tokens: Option<i64>,
}

/// A stored build variant, as what it was rather than as the hash it is
/// known by.
///
/// The description is optional throughout: a variant recorded before a run
/// wrote down what it was analysed under says nothing here, which is not the
/// same claim as a build that was resolved and had nothing to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVariant {
    /// Row id of the variant.
    pub id: i64,
    /// Its fingerprint, which is what results are attributed to.
    pub fingerprint: String,
    /// Analysis mode name.
    pub analysis_mode: String,
    /// The languages the run enumerated, comma-separated in a fixed order.
    pub languages: Option<String>,
    /// The grammar bare `.h` headers were read with; empty when the run
    /// enumerated neither C nor C++.
    pub header_language: Option<String>,
    /// Which language's build was resolved; empty when none was.
    pub build_language: Option<String>,
    /// What the compiler was told, in the order it was told, grouped by
    /// setting name.
    pub settings: Vec<StoredSetting>,
}

/// One recorded value of one build setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSetting {
    /// The setting's stable name.
    pub name: String,
    /// Its position within that setting, for the ones that are sequences.
    pub position: i64,
    /// The value as it was given.
    pub value: String,
}

/// One stored occurrence of a group's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMember {
    /// Hex form of the occurrence's stable finding id.
    pub finding_hex: String,
    /// Hex form of the content fingerprint of the matched slice.
    ///
    /// Two occurrences of the same content share it, which is what makes a
    /// result exported from one machine comparable with a run on another: the
    /// finding id is derived from the group fingerprint and moves with it,
    /// while this does not.
    pub content_hex: String,
    /// Language the occurrence was read as (`rust`, `c`, `cpp`).
    pub language: String,
    /// Anchor: file path relative to the scan root.
    pub file_path: String,
    /// Anchor: 1-based first line.
    pub start_line: Option<i64>,
    /// Anchor: 1-based last line.
    pub end_line: Option<i64>,
    /// Size in tokens.
    pub token_count: i64,
    /// Name of the enclosing unit, when anchored to one.
    pub unit_name: Option<String>,
    /// Whether this is the group's canonical instance.
    pub is_canonical: bool,
}

/// One stored clone group with its members.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredGroup {
    /// Hex form of the group fingerprint.
    pub fingerprint_hex: String,
    /// Clone classification name (`type-1`, `type-2`, ...).
    pub clone_type: String,
    /// What the members are: `unit` for whole duplicated units, `fragment`
    /// for a run of statements duplicated inside them.
    pub member_scope: String,
    /// Minimum pairwise raw similarity.
    pub score: f64,
    /// Content entropy in bits.
    pub entropy_bits: f64,
    /// Noise marker name, if one fired.
    pub suppress_reason: Option<String>,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether the group is a verified pair no larger group could hold, and
    /// so the one kind whose members appear in another group too.
    pub split_pair: bool,
    /// Whether every member is test code.
    pub test_code: bool,
    /// Whether the members differ from each other by one integer width and
    /// nothing else.
    pub width_family: bool,
    /// Statements each member covers, for a fragment-scope group; `None` for a
    /// whole-unit group, and for a row written before runs recorded it.
    pub statements: Option<i64>,
    /// The similarity breakdown, when the mode measured one (Structural).
    pub similarity: Option<StoredSimilarity>,
    /// The rule that hid the group in its run, when one matched. Absent for a
    /// group the run reported.
    pub suppressed_by: Option<StoredSuppressionRef>,
    /// The group's occurrences.
    pub members: Vec<StoredMember>,
}

/// A stored group's similarity breakdown, one measured dimension per field.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredSimilarity {
    /// The composite-weight recipe version.
    pub weight_version: String,
    /// Verbatim leading-token agreement.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement.
    pub control_flow: f64,
    /// Type agreement, or `None` when types were unavailable.
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement, or `None` when neither unit called
    /// anything.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group.
    pub min_pairwise: f64,
    /// The band the verdict was assigned, or `None` for a row written before
    /// the band was recorded. A band is a judgement, so an absent one is
    /// reported as absent rather than derived from the numbers after the fact.
    pub confidence_band: Option<String>,
}

/// One stored finding: the audited row of a group in a run.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredFinding {
    /// Hex form of the group fingerprint the finding audits.
    pub group_fingerprint_hex: String,
    /// Audit state (`new`, `unchanged`, `resolved`, ...).
    pub audit_state: String,
    /// Clone confidence.
    pub clone_confidence: f64,
    /// Final priority; the derivation inputs stay on the group and its
    /// members rather than being collapsed into this one number.
    pub final_priority: f64,
    /// Scope of the suppression rule that suppressed the finding, if any
    /// (for example `path_glob` or `inline_comment`).
    pub suppression_scope: Option<String>,
}

/// Detail of one occurrence, looked up by its finding id (for `explain`).
///
/// The lookup carries the owning group's evidence, not just its identity: an
/// occurrence is only interesting together with what made it a finding.
#[derive(Debug, Clone, PartialEq)]
pub struct OccurrenceDetail {
    /// The occurrence itself.
    pub member: StoredMember,
    /// Hex form of the owning group's fingerprint.
    pub group_fingerprint_hex: String,
    /// The owning group's clone type name.
    pub clone_type: String,
    /// What the owning group's members are (`unit` or `fragment`).
    pub member_scope: String,
    /// The owning group's score.
    pub score: f64,
    /// Number of occurrences in the owning group, this one included.
    pub member_count: i64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether every member of the owning group is test code.
    pub test_code: bool,
    /// Whether the owning group is a verified pair no larger group could hold.
    pub split_pair: bool,
    /// The owning group's similarity breakdown, when the mode measured one.
    pub similarity: Option<StoredSimilarity>,
    /// Where the run ranked the finding, and the facts it ranked on. Absent
    /// for a group with no audited finding row.
    pub priority: Option<StoredPriority>,
    /// The rule that suppressed the finding in this run, if one matched.
    pub suppression: Option<StoredSuppressionRef>,
    /// Row id of the scan run the occurrence belongs to.
    pub scan_run_id: i64,
}

/// Where a stored run ranked a finding, and what it read to get there.
///
/// Read back rather than recomputed. The rules a run ranked under are the
/// rules that release carried, and re-deriving the number under today's would
/// answer a question nobody asked — the recorded value is what the run acted
/// on. Every measure a run did not take is `None`, including the ones a newer
/// release computes and an older one did not.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredPriority {
    /// How sure the finding was duplication worth reporting.
    pub clone_confidence: f64,
    /// What keeping the copies in step was judged to cost.
    pub maintenance_risk: Option<f64>,
    /// What removing the duplication was judged to cost.
    pub refactoring_difficulty: Option<f64>,
    /// The composed ranking value.
    pub final_priority: f64,
    /// How sure the finding is semantically equivalent.
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact.
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are.
    pub savings_confidence: Option<f64>,
    /// The group facts the measures were read from.
    pub facts: StoredRankingFacts,
}

/// What a stored group looks like to the ranking.
///
/// Derived from the group's own rows rather than stored a second time: a copy
/// of a derivable value is a second answer waiting to disagree with the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredRankingFacts {
    /// Token count of the smallest occurrence.
    pub smallest_member_tokens: i64,
    /// Token count of the largest occurrence.
    pub largest_member_tokens: i64,
    /// Occurrences in the group.
    pub instances: i64,
    /// Distinct files the occurrences sit in.
    pub files: i64,
    /// Distinct directories the occurrences sit in.
    pub directories: i64,
    /// Distinct languages the occurrences are written in.
    pub languages: i64,
    /// The run's minimum clone length. `None` for a run recorded before runs
    /// stored the floor they reported under.
    pub min_clone_tokens: Option<i64>,
}

/// The suppression rule a finding references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSuppressionRef {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`, ...).
    pub scope: String,
    /// The rule's pattern.
    pub pattern: String,
}

/// One posting-list entry: an occurrence of a feature hash at a location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureOccurrence {
    /// Run the occurrence was recorded in.
    pub scan_run_id: i64,
    /// Enclosing unit row, when anchored to one.
    pub source_unit_id: Option<i64>,
    /// Anchor: first byte covered.
    pub start_byte: i64,
    /// Anchor: one past the last byte covered.
    pub end_byte: i64,
    /// Kind-specific size (window length, subtree node count, ...).
    pub extent: i64,
}

impl Store {
    /// The posting list of one feature hash: every occurrence of `kind`/`hash`,
    /// deterministically ordered by run, unit and anchor. This is the read the
    /// candidate index builds on.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn feature_posting_list(
        &self,
        kind: FeatureKind,
        hash: &[u8; 16],
    ) -> Result<Vec<FeatureOccurrence>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT o.scan_run_id, o.source_unit_id, o.start_byte, o.end_byte, o.extent
             FROM feature_occurrence o
             JOIN feature_fingerprint f ON f.id = o.feature_fingerprint_id
             WHERE f.kind = ?1 AND f.hash = ?2
             ORDER BY o.scan_run_id ASC, o.source_unit_id ASC, o.start_byte ASC, o.id ASC",
        )?;
        let rows = stmt
            .query_map(params![kind.name(), hash.as_slice()], |row| {
                Ok(FeatureOccurrence {
                    scan_run_id: row.get(0)?,
                    source_unit_id: row.get(1)?,
                    start_byte: row.get(2)?,
                    end_byte: row.get(3)?,
                    extent: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    }

    /// The most recently started scan run, if any.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_run(&self) -> Result<Option<RunSummary>, StoreError> {
        self.conn
            .query_row(
                "SELECT r.id, r.root_path, r.tool_version, r.analysis_mode,
                        r.started_at, r.finished_at,
                        (SELECT COUNT(*) FROM clone_group g WHERE g.scan_run_id = r.id)
                 FROM scan_run r
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                [],
                |row| {
                    Ok(RunSummary {
                        id: row.get(0)?,
                        root_path: row.get(1)?,
                        tool_version: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        group_count: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// The most recent completed run over `root_path` under `variant`, and
    /// the tree it read.
    ///
    /// A run is comparable with this one only when it looked at the same tree
    /// under the same build variant: a file whose bytes did not move still
    /// has to be re-analysed when the rules for analysing it did. Both are
    /// therefore part of the lookup rather than checks made afterwards.
    ///
    /// Returns `None` when no such run exists, which is the ordinary state of
    /// a first scan and not an error. A run that recorded no files — every
    /// run written before the tree was recorded at all — answers the same
    /// way, because "read nothing" and "did not say" are not distinguishable
    /// after the fact and the safe reading is the second.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn previous_tree(
        &self,
        root_path: &str,
        variant_fingerprint: &str,
    ) -> Result<Option<PreviousTree>, StoreError> {
        let Some(run_id) = self.completed_run_id(root_path, Some(variant_fingerprint))? else {
            return Ok(None);
        };
        let tree: BTreeMap<PathBuf, String> = self
            .run_tree(run_id)?
            .into_iter()
            .map(|(path, hash)| (PathBuf::from(path), hash))
            .collect();
        if tree.is_empty() {
            return Ok(None);
        }
        Ok(Some((run_id, tree)))
    }

    /// The files one run read, by path relative to the scan root, each with
    /// the hash of what it held.
    ///
    /// Empty for a run that recorded no files, which is every run written
    /// before the tree was recorded at all. "Read nothing" and "did not say"
    /// are not distinguishable after the fact, so a caller that needs the
    /// difference has to decide what an empty answer means to it.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_tree(&self, run_id: i64) -> Result<BTreeMap<String, String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT relative_path, content_hash FROM scanned_file
             WHERE scan_run_id = ?1
             ORDER BY relative_path",
        )?;
        let mut tree = BTreeMap::new();
        for row in stmt.query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })? {
            let (path, hash) = row?;
            tree.insert(path, hash);
        }
        Ok(tree)
    }

    /// Row id of the newest completed run over `root_path` under `variant`,
    /// which is the run a scan about to record compares itself against.
    ///
    /// Unlike [`Self::previous_tree`] this answers even for a run that
    /// recorded no files: what a run found is recorded whether or not what it
    /// read was, and the findings are what a lineage comparison reads.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn previous_run(
        &self,
        root_path: &str,
        variant_fingerprint: &str,
    ) -> Result<Option<i64>, StoreError> {
        self.completed_run_id(root_path, Some(variant_fingerprint))
    }

    /// Row id of the newest completed run over `root_path`, optionally
    /// narrowed to one build variant.
    ///
    /// Narrowing is what makes two runs comparable file by file; leaving it
    /// open is for the callers that read a run in order to *record* which
    /// variant it used, and so cannot name it in advance.
    fn completed_run_id(
        &self,
        root_path: &str,
        variant_fingerprint: Option<&str>,
    ) -> Result<Option<i64>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT r.id
                 FROM scan_run r
                 JOIN build_variant v ON v.id = r.build_variant_id
                 WHERE r.root_path = ?1
                   AND (?2 IS NULL OR v.variant_fingerprint = ?2)
                   AND r.status = 'completed'
                 ORDER BY r.started_at DESC, r.id DESC
                 LIMIT 1",
                params![root_path, variant_fingerprint],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// What the newest completed run over `root_path` under `variant` was told
    /// to do, or `None` when there is no such run or it never finished.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn previous_run_record(
        &self,
        root_path: &str,
        variant_fingerprint: &str,
    ) -> Result<Option<RunRecord>, StoreError> {
        let Some(run_id) = self.completed_run_id(root_path, Some(variant_fingerprint))? else {
            return Ok(None);
        };
        Ok(self
            .conn
            .query_row(
                "SELECT root_path, tool_version, config_hash, analysis_mode,
                        started_at, finished_at, min_clone_tokens
                 FROM scan_run WHERE id = ?1 AND finished_at IS NOT NULL",
                params![run_id],
                |row| {
                    Ok(RunRecord {
                        id: run_id,
                        root_path: row.get(0)?,
                        tool_version: row.get(1)?,
                        config_hash: row.get(2)?,
                        analysis_mode: row.get(3)?,
                        started_at: row.get(4)?,
                        finished_at: row.get(5)?,
                        min_clone_tokens: row.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    /// How many files of each language a run read, by language name.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_language_counts(&self, run_id: i64) -> Result<BTreeMap<String, u64>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT language, count(*) FROM scanned_file
             WHERE scan_run_id = ?1 GROUP BY language ORDER BY language",
        )?;
        let mut counts = BTreeMap::new();
        for row in stmt.query_map(params![run_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })? {
            let (language, count) = row?;
            counts.insert(language, u64::try_from(count).unwrap_or(0));
        }
        Ok(counts)
    }

    /// The newest completed run over `root_path`, with the identity a
    /// judgement about its results has to be qualified by.
    ///
    /// Unlike [`Self::previous_tree`] this does not narrow to a variant: the
    /// caller is reading a run in order to record what it was, so the variant
    /// is an answer rather than a question.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_completed_run(&self, root_path: &str) -> Result<Option<RunOrigin>, StoreError> {
        let Some(run_id) = self.completed_run_id(root_path, None)? else {
            return Ok(None);
        };
        self.run_origin(run_id).map(Some)
    }

    /// The identity of one run by row id: the conditions its stable ids were
    /// computed under, which every judgement about its results is qualified
    /// by.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error, including the case of a run id
    /// this database does not hold.
    pub fn run_origin(&self, run_id: i64) -> Result<RunOrigin, StoreError> {
        let mut origin = self.conn.query_row(
            "SELECT r.root_path, r.tool_version, r.analysis_mode, r.finished_at,
                    v.variant_fingerprint, v.normalization_version
             FROM scan_run r
             JOIN build_variant v ON v.id = r.build_variant_id
             WHERE r.id = ?1",
            params![run_id],
            |row| {
                Ok(RunOrigin {
                    id: run_id,
                    root_path: row.get(0)?,
                    tool_version: row.get(1)?,
                    analysis_mode: row.get(2)?,
                    finished_at: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    variant_fingerprint: row.get(4)?,
                    normalization_version: row.get(5)?,
                    detector_versions: Vec::new(),
                })
            },
        )?;
        let mut stmt = self.conn.prepare(
            "SELECT d.component, d.version
             FROM scan_run_detector_version rd
             JOIN detector_version d ON d.id = rd.detector_version_id
             WHERE rd.scan_run_id = ?1
             ORDER BY d.component ASC, d.version ASC",
        )?;
        origin.detector_versions = stmt
            .query_map(params![run_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        Ok(origin)
    }

    /// What the variant `fingerprint` names was analysed under, or `None` when
    /// this database holds no such variant.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn build_variant(&self, fingerprint: &str) -> Result<Option<StoredVariant>, StoreError> {
        let Some(mut variant) = self
            .conn
            .query_row(
                "SELECT id, variant_fingerprint, analysis_mode, languages,
                        header_language, build_language
                 FROM build_variant
                 WHERE variant_fingerprint = ?1",
                params![fingerprint],
                |row| {
                    Ok(StoredVariant {
                        id: row.get(0)?,
                        fingerprint: row.get(1)?,
                        analysis_mode: row.get(2)?,
                        languages: row.get(3)?,
                        header_language: row.get(4)?,
                        build_language: row.get(5)?,
                        settings: Vec::new(),
                    })
                },
            )
            .optional()?
        else {
            return Ok(None);
        };
        let mut stmt = self.conn.prepare(
            "SELECT name, position, value
             FROM build_variant_setting
             WHERE build_variant_id = ?1
             ORDER BY name ASC, position ASC",
        )?;
        variant.settings = stmt
            .query_map(params![variant.id], |row| {
                Ok(StoredSetting {
                    name: row.get(0)?,
                    position: row.get(1)?,
                    value: row.get(2)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(Some(variant))
    }

    /// Every completed run over `root_path`, newest first, at most `limit` of
    /// them.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn completed_runs(
        &self,
        root_path: &str,
        limit: usize,
    ) -> Result<Vec<RunOrigin>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id
             FROM scan_run r
             WHERE r.root_path = ?1 AND r.status = 'completed'
             ORDER BY r.started_at DESC, r.id DESC
             LIMIT ?2",
        )?;
        let ids: Vec<i64> = stmt
            .query_map(
                params![root_path, i64::try_from(limit).unwrap_or(i64::MAX)],
                |row| row.get(0),
            )?
            .collect::<Result<_, _>>()?;
        ids.into_iter().map(|id| self.run_origin(id)).collect()
    }

    /// Every clone group of `run_id` reduced to what history compares:
    /// content fingerprints, anchors, and the lineage the run recorded.
    ///
    /// Read in one pass rather than through [`Self::run_groups`], which fans
    /// out into per-group queries for evidence a comparison never looks at.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownVocabulary`] when a row names a clone type or
    /// member scope this build does not know; otherwise any underlying
    /// database error.
    pub fn run_group_snapshots(&self, run_id: i64) -> Result<Vec<GroupSnapshot>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(gf.hash)), g.clone_type, g.member_scope, g.score,
                    lower(hex(ff.hash)), fr.file_path, u.name, m.is_canonical,
                    lower(hex(gl.lineage_id))
             FROM clone_group g
             JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
             JOIN clone_group_member m ON m.clone_group_id = g.id
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             LEFT JOIN source_unit u ON u.id = fr.source_unit_id
             LEFT JOIN group_lineage gl ON gl.scan_run_id = g.scan_run_id
                                       AND gl.group_fingerprint_id = g.group_fingerprint_id
             WHERE g.scan_run_id = ?1
             ORDER BY gf.hash ASC, fr.file_path ASC, fr.start_line ASC, fr.id ASC",
        )?;
        let rows = stmt.query_map(params![run_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, i64>(7)? != 0,
                row.get::<_, Option<String>>(8)?,
            ))
        })?;

        let mut groups: Vec<GroupSnapshot> = Vec::new();
        for row in rows {
            let (
                fingerprint,
                clone_type,
                member_scope,
                score,
                content,
                file,
                unit,
                canonical,
                lineage,
            ) = row?;
            let content = FragmentFingerprint::from_bytes(parse_hex_id(&content)?);
            if groups
                .last()
                .is_none_or(|group| group.fingerprint.to_hex() != fingerprint)
            {
                groups.push(GroupSnapshot {
                    fingerprint: CloneGroupFingerprint::from_bytes(parse_hex_id(&fingerprint)?),
                    clone_type: CloneClass::from_name(&clone_type).ok_or_else(|| {
                        StoreError::UnknownVocabulary {
                            field: "clone_type",
                            value: clone_type.clone(),
                        }
                    })?,
                    scope: CloneScope::from_name(&member_scope).ok_or_else(|| {
                        StoreError::UnknownVocabulary {
                            field: "member_scope",
                            value: member_scope.clone(),
                        }
                    })?,
                    score,
                    canonical: None,
                    lineage: lineage
                        .as_deref()
                        .map(parse_hex_id)
                        .transpose()?
                        .map(GroupLineageId::from_bytes),
                    members: Vec::new(),
                });
            }
            let Some(group) = groups.last_mut() else {
                continue;
            };
            if canonical {
                group.canonical = Some(content);
            }
            group.members.push(MemberSnapshot {
                content,
                anchor: Anchor { file, unit },
            });
        }
        Ok(groups)
    }

    /// Every clone group of `run_id`, deterministically ordered by
    /// fingerprint bytes, each with its members.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_groups(&self, run_id: i64) -> Result<Vec<StoredGroup>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT g.id, lower(hex(f.hash)), g.clone_type, g.score, g.entropy_bits,
                    g.suppress_reason, g.boilerplate, g.member_scope, g.test_code,
                    g.split_pair, s.scope, s.pattern, g.width_family, g.statements
             FROM clone_group g
             JOIN fingerprint f ON f.id = g.group_fingerprint_id
             LEFT JOIN finding fi ON fi.clone_group_id = g.id
             LEFT JOIN suppression s ON s.id = fi.suppression_id
             WHERE g.scan_run_id = ?1
             ORDER BY f.hash ASC",
        )?;
        let rows: Vec<(i64, StoredGroup)> = stmt
            .query_map(params![run_id], |row| {
                let scope: Option<String> = row.get(10)?;
                let pattern: Option<String> = row.get(11)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    StoredGroup {
                        fingerprint_hex: row.get(1)?,
                        clone_type: row.get(2)?,
                        member_scope: row.get(7)?,
                        score: row.get(3)?,
                        entropy_bits: row.get(4)?,
                        suppress_reason: row.get(5)?,
                        boilerplate: row.get(6)?,
                        test_code: row.get(8)?,
                        split_pair: row.get(9)?,
                        width_family: row.get(12)?,
                        statements: row.get(13)?,
                        similarity: None,
                        suppressed_by: scope
                            .zip(pattern)
                            .map(|(scope, pattern)| StoredSuppressionRef { scope, pattern }),
                        members: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<_, _>>()?;

        let mut groups = Vec::with_capacity(rows.len());
        for (group_row_id, mut group) in rows {
            group.similarity = self.group_similarity(group_row_id)?;
            group.members = self.group_members(group_row_id)?;
            groups.push(group);
        }
        Ok(groups)
    }

    /// What the run reported about itself beyond its findings, or `None` for a
    /// run recorded before runs stored it.
    ///
    /// Absent means the run cannot be described again, not that it measured
    /// nothing — a caller rebuilding a report from a stored run has to treat
    /// the two differently.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_summary_row(&self, run_id: i64) -> Result<Option<SummaryRow>, StoreError> {
        let summary = self
            .conn
            .query_row(
                "SELECT lines, tokens, lexer_diagnostics, unparsed_files,
                        unparsed_tokens, excluded_generated, excluded_by_glob,
                        excluded_skipped, folded_runs, subsumed_runs,
                        split_components, pair_budget_exhausted, baseline_digest
                 FROM run_summary WHERE scan_run_id = ?1",
                params![run_id],
                |row| {
                    let count = |value: i64| u64::try_from(value).unwrap_or(0);
                    let files: Option<i64> = row.get(3)?;
                    let tokens: Option<i64> = row.get(4)?;
                    Ok(SummaryRow {
                        lines: count(row.get(0)?),
                        tokens: count(row.get(1)?),
                        lexer_diagnostics: count(row.get(2)?),
                        unparsed: files.zip(tokens).map(|(files, tokens)| UnparsedRow {
                            files: count(files),
                            tokens: count(tokens),
                        }),
                        excluded_generated: count(row.get(5)?),
                        excluded_by_glob: count(row.get(6)?),
                        excluded_skipped: count(row.get(7)?),
                        folded_runs: count(row.get(8)?),
                        subsumed_runs: count(row.get(9)?),
                        split_components: count(row.get(10)?),
                        pair_budget_exhausted: row.get(11)?,
                        baseline_digest: row.get(12)?,
                        funnel: Vec::new(),
                        unused_suppressions: Vec::new(),
                    })
                },
            )
            .optional()?;
        let Some(mut summary) = summary else {
            return Ok(None);
        };
        summary.funnel = self.run_funnel(run_id)?;
        summary.unused_suppressions = self.run_unused_suppressions(run_id)?;
        Ok(Some(summary))
    }

    /// The run's candidate pipeline, stage by stage in run order, each stage
    /// carrying what it dropped.
    fn run_funnel(&self, run_id: i64) -> Result<Vec<FunnelStageRow>, StoreError> {
        let mut stages = self
            .conn
            .prepare(
                "SELECT position, name, passed FROM run_funnel_stage
                 WHERE scan_run_id = ?1 ORDER BY position ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    FunnelStageRow {
                        name: row.get(1)?,
                        passed: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                        dropped: Vec::new(),
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let drops = self
            .conn
            .prepare(
                "SELECT position, cause, dropped FROM run_funnel_drop
                 WHERE scan_run_id = ?1 ORDER BY position ASC, ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    FunnelDropRow {
                        cause: row.get(1)?,
                        count: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                    },
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for (position, drop) in drops {
            if let Some((_, stage)) = stages.iter_mut().find(|(at, _)| *at == position) {
                stage.dropped.push(drop);
            }
        }
        Ok(stages.into_iter().map(|(_, stage)| stage).collect())
    }

    /// The configured rules the run found nothing for, in the order it named
    /// them.
    fn run_unused_suppressions(&self, run_id: i64) -> Result<Vec<UnusedRuleRow>, StoreError> {
        Ok(self
            .conn
            .prepare(
                "SELECT scope, pattern FROM run_unused_suppression
                 WHERE scan_run_id = ?1 ORDER BY ordinal ASC",
            )?
            .query_map(params![run_id], |row| {
                Ok(UnusedRuleRow {
                    scope: row.get(0)?,
                    pattern: row.get(1)?,
                })
            })?
            .collect::<Result<_, _>>()?)
    }

    /// The similarity breakdown of one group row, or `None` when the mode
    /// measured none (Fast).
    fn group_similarity(&self, group_row_id: i64) -> Result<Option<StoredSimilarity>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT weight_version, lexical, structural, control_flow,
                        type_similarity, api, composite, min_pairwise,
                        confidence_band
                 FROM clone_group_similarity
                 WHERE clone_group_id = ?1",
                params![group_row_id],
                |row| {
                    Ok(StoredSimilarity {
                        weight_version: row.get(0)?,
                        lexical: row.get(1)?,
                        structural: row.get(2)?,
                        control_flow: row.get(3)?,
                        type_similarity: row.get(4)?,
                        api: row.get(5)?,
                        composite: row.get(6)?,
                        min_pairwise: row.get(7)?,
                        confidence_band: row.get(8)?,
                    })
                },
            )
            .optional()?)
    }

    /// The members of one group row, in the order the run recorded them.
    ///
    /// Fragment rows are written as the run listed the occurrences, so their
    /// row ids carry that order and the canonical instance comes first. Any
    /// other ordering would be this layer's opinion rather than the run's, and
    /// a report rebuilt from these rows has to list what the run listed.
    fn group_members(&self, group_row_id: i64) -> Result<Vec<StoredMember>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                    fr.token_count, u.name, m.is_canonical, lower(hex(ff.hash)),
                    ff.language
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             LEFT JOIN source_unit u ON u.id = fr.source_unit_id
             WHERE m.clone_group_id = ?1
             ORDER BY fr.id ASC",
        )?;
        let members = stmt
            .query_map(params![group_row_id], |row| map_member(row, 7))?
            .collect::<Result<_, _>>()?;
        Ok(members)
    }

    /// Every finding of `run_id`, ordered by group fingerprint bytes.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_findings(&self, run_id: i64) -> Result<Vec<StoredFinding>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lower(hex(gf.hash)), fi.audit_state, fi.clone_confidence, fi.final_priority,
                    s.scope
             FROM finding fi
             JOIN clone_group g ON g.id = fi.clone_group_id
             JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
             LEFT JOIN suppression s ON s.id = fi.suppression_id
             WHERE fi.scan_run_id = ?1
             ORDER BY gf.hash ASC",
        )?;
        let findings = stmt
            .query_map(params![run_id], |row| {
                Ok(StoredFinding {
                    group_fingerprint_hex: row.get(0)?,
                    audit_state: row.get(1)?,
                    clone_confidence: row.get(2)?,
                    final_priority: row.get(3)?,
                    suppression_scope: row.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(findings)
    }

    /// Number of rows in `table` — a diagnostic for `doctor`/`cache status`
    /// and tests. The name is validated against the schema first, so this
    /// never interpolates arbitrary input into SQL.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnknownTable`] when `table` is not a known table;
    /// otherwise any underlying database error.
    pub fn table_count(&self, table: &str) -> Result<i64, StoreError> {
        let known: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get(0),
        )?;
        if known != 1 {
            return Err(StoreError::UnknownTable {
                table: table.to_string(),
            });
        }
        Ok(self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })?)
    }

    /// Look up one occurrence by the hex form of its finding id.
    ///
    /// # Errors
    ///
    /// [`StoreError::MalformedId`] when `finding_hex` is not 32 hex digits;
    /// otherwise any underlying database error.
    pub fn occurrence(&self, finding_hex: &str) -> Result<Option<OccurrenceDetail>, StoreError> {
        let bytes = parse_hex_id(finding_hex)?;
        let found = self
            .conn
            .query_row(
                "SELECT lower(hex(m.finding_id)), fr.file_path, fr.start_line, fr.end_line,
                        fr.token_count, u.name, m.is_canonical,
                        lower(hex(gf.hash)), g.clone_type, g.score, g.scan_run_id,
                        g.member_count, g.boilerplate, s.scope, s.pattern, g.id,
                        g.member_scope, g.test_code, g.split_pair, lower(hex(ff.hash)),
                        ff.language
                 FROM clone_group_member m
                 JOIN fragment fr ON fr.id = m.fragment_id
                 JOIN fingerprint ff ON ff.id = fr.fingerprint_id
                 LEFT JOIN source_unit u ON u.id = fr.source_unit_id
                 JOIN clone_group g ON g.id = m.clone_group_id
                 JOIN fingerprint gf ON gf.id = g.group_fingerprint_id
                 LEFT JOIN finding fi ON fi.clone_group_id = g.id
                                     AND fi.scan_run_id = g.scan_run_id
                 LEFT JOIN suppression s ON s.id = fi.suppression_id
                 WHERE m.finding_id = ?1
                 ORDER BY g.scan_run_id DESC
                 LIMIT 1",
                params![bytes.as_slice()],
                |row| {
                    let suppression = row
                        .get::<_, Option<String>>(13)?
                        .map(|scope| -> Result<_, rusqlite::Error> {
                            Ok(StoredSuppressionRef {
                                scope,
                                pattern: row.get(14)?,
                            })
                        })
                        .transpose()?;
                    Ok((
                        OccurrenceDetail {
                            member: map_member(row, 19)?,
                            group_fingerprint_hex: row.get(7)?,
                            clone_type: row.get(8)?,
                            member_scope: row.get(16)?,
                            score: row.get(9)?,
                            scan_run_id: row.get(10)?,
                            member_count: row.get(11)?,
                            boilerplate: row.get(12)?,
                            test_code: row.get(17)?,
                            split_pair: row.get(18)?,
                            similarity: None,
                            priority: None,
                            suppression,
                        },
                        row.get::<_, i64>(15)?,
                    ))
                },
            )
            .optional()?;
        let Some((mut detail, group_row_id)) = found else {
            return Ok(None);
        };
        detail.similarity = self.group_similarity(group_row_id)?;
        detail.priority = self.group_priority(group_row_id, detail.scan_run_id)?;
        Ok(Some(detail))
    }

    /// Where a run ranked one group's finding, with the facts behind it.
    fn group_priority(
        &self,
        group_row_id: i64,
        run_id: i64,
    ) -> Result<Option<StoredPriority>, StoreError> {
        let facts = self.ranking_facts(group_row_id, run_id)?;
        Ok(self
            .conn
            .query_row(
                "SELECT clone_confidence, maintenance_risk, refactoring_difficulty,
                        final_priority, semantic_confidence,
                        source_artifact_mapping_confidence, savings_confidence
                 FROM finding
                 WHERE clone_group_id = ?1 AND scan_run_id = ?2",
                params![group_row_id, run_id],
                |row| {
                    Ok(StoredPriority {
                        clone_confidence: row.get(0)?,
                        maintenance_risk: row.get(1)?,
                        refactoring_difficulty: row.get(2)?,
                        final_priority: row.get(3)?,
                        semantic_confidence: row.get(4)?,
                        source_artifact_confidence: row.get(5)?,
                        savings_confidence: row.get(6)?,
                        facts,
                    })
                },
            )
            .optional()?)
    }

    /// One stored group as the ranking reads it.
    ///
    /// The directory count is taken in Rust rather than in SQL: splitting a
    /// path is not something an expression over `TEXT` does readably, and the
    /// member count of a group is small enough that reading the paths costs
    /// nothing.
    fn ranking_facts(
        &self,
        group_row_id: i64,
        run_id: i64,
    ) -> Result<StoredRankingFacts, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT fr.file_path, fr.token_count, ff.language
             FROM clone_group_member m
             JOIN fragment fr ON fr.id = m.fragment_id
             JOIN fingerprint ff ON ff.id = fr.fingerprint_id
             WHERE m.clone_group_id = ?1",
        )?;
        let rows = statement.query_map(params![group_row_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        let mut tokens: Vec<i64> = Vec::new();
        let mut files: BTreeSet<String> = BTreeSet::new();
        let mut directories: BTreeSet<String> = BTreeSet::new();
        let mut languages: BTreeSet<String> = BTreeSet::new();
        for row in rows {
            let (path, token_count, language) = row?;
            tokens.push(token_count);
            directories.insert(
                path.rfind('/')
                    .map_or_else(String::new, |cut| path[..cut].to_string()),
            );
            files.insert(path);
            languages.insert(language);
        }
        let min_clone_tokens = self.conn.query_row(
            "SELECT min_clone_tokens FROM scan_run WHERE id = ?1",
            params![run_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(StoredRankingFacts {
            smallest_member_tokens: tokens.iter().copied().min().unwrap_or(0),
            largest_member_tokens: tokens.iter().copied().max().unwrap_or(0),
            instances: i64::try_from(tokens.len()).unwrap_or(i64::MAX),
            files: i64::try_from(files.len()).unwrap_or(i64::MAX),
            directories: i64::try_from(directories.len()).unwrap_or(i64::MAX),
            languages: i64::try_from(languages.len()).unwrap_or(i64::MAX),
            min_clone_tokens,
        })
    }
}

/// Read one member from a row whose first seven columns are the member's, and
/// whose content and language columns start at `content` — the two queries
/// that select members place the pair differently but always adjacently.
fn map_member(row: &rusqlite::Row<'_>, content: usize) -> Result<StoredMember, rusqlite::Error> {
    Ok(StoredMember {
        finding_hex: row.get(0)?,
        content_hex: row.get(content)?,
        language: row.get(content + 1)?,
        file_path: row.get(1)?,
        start_line: row.get(2)?,
        end_line: row.get(3)?,
        token_count: row.get(4)?,
        unit_name: row.get(5)?,
        is_canonical: row.get::<_, i64>(6)? != 0,
    })
}

/// Parse a 32-digit hex identifier into its 16 bytes.
pub(crate) fn parse_hex_id(hex: &str) -> Result<[u8; 16], StoreError> {
    let malformed = || StoreError::MalformedId {
        id: hex.to_string(),
    };
    if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let pair = core::str::from_utf8(chunk).map_err(|_| malformed())?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_parse_and_reject_malformed_input() {
        let parsed = parse_hex_id("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(parsed[0], 0);
        assert_eq!(parsed[15], 0x0f);
        assert!(parse_hex_id("").is_err());
        assert!(parse_hex_id("zz0102030405060708090a0b0c0d0e0f").is_err());
        assert!(parse_hex_id("00010203").is_err());
    }
}
