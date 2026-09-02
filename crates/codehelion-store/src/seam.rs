//! Recorded seam runs: what one evaluation of the seam ledger against the git
//! history found, kept so two generations of the same measurement can be
//! compared.
//!
//! A seam is a set of repository-relative path globs that implement the same
//! semantics in more than one place; a seam run is one evaluation of that
//! ledger, producing per-seam counts. The records here are plain rows rather
//! than the ledger's own types, so this crate stays free of a git
//! implementation and the caller converts.
//!
//! Two things this module is deliberate about:
//!
//! - Comparison is scoped by the settings the run was computed under. Two runs
//!   taken under different settings are not two generations of one
//!   measurement, and a trend across them would report a settings change as a
//!   change in the code.
//! - A finding is read for its location and nothing else. The seam mapping
//!   asks where a finding is, never how severe it is, so no severity, score or
//!   text leaves the store through this path.

use rusqlite::{OptionalExtension, Row, params};

use crate::{Store, StoreError};

/// Ordering that decides which recorded seam run is the newest.
///
/// Reading the latest run and stepping back to the one before it both use this
/// order, so the run a comparison calls "the previous generation" is always the
/// run that directly precedes the one it started from.
pub(crate) const SEAM_RUN_RECENCY: &str = "recorded_at DESC, id DESC";

/// What one seam run found for one seam of the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeamEntryRecord {
    /// The ledger's name for this seam.
    pub seam_id: String,
    /// Repository-relative path globs the seam spans.
    pub members: Vec<String>,
    /// What the ledger says this seam is, when it says anything.
    pub note: Option<String>,
    /// Commits that touched some members of the seam but not all of them.
    pub asymmetric_changes: i64,
    /// Asymmetric changes the run judged to have broken the seam.
    pub breaches: i64,
    /// Commit of the most recent breach, when there was one.
    pub last_breach: Option<String>,
    /// Recorded findings whose location falls inside the seam.
    pub findings: i64,
}

/// One evaluation of the seam ledger against a repository's history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeamRunRecord {
    /// Repository root the ledger was evaluated against.
    pub root_path: String,
    /// Digest of the settings the run was computed under.
    pub settings_digest: String,
    /// Oldest commit in the examined range, when the range had one.
    pub first_commit: Option<String>,
    /// Newest commit in the examined range, when the range had one.
    pub last_commit: Option<String>,
    /// Commits examined, which may be none.
    pub commit_count: i64,
    /// Scan run whose findings this run mapped onto the ledger, if any.
    pub scan_run_id: Option<i64>,
    /// RFC 3339 time the run was recorded.
    pub recorded_at: String,
    /// The ledger's seams, in the order it wrote them.
    pub entries: Vec<SeamEntryRecord>,
}

/// A seam run as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSeamRun {
    /// Row id of the run.
    pub id: i64,
    /// What the run recorded.
    pub run: SeamRunRecord,
}

/// One finding's location, which is all a seam mapping reads of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingLocation {
    /// Path the finding's fragment was recorded at.
    pub file_path: String,
    /// First line of that fragment, or zero when the run recorded none.
    pub start_line: i64,
}

impl Store {
    /// Record one evaluation of the seam ledger and return its row id.
    ///
    /// The run and every entry are written in one transaction, so a ledger is
    /// never half recorded: a reader sees the whole evaluation or no run at
    /// all. Entries keep the order they are given, which is the order the
    /// ledger wrote them.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidSeamEntry`] for an entry with no name, no
    /// members, or a member a stored row could not be read back from;
    /// otherwise any underlying database error.
    pub fn record_seam_run(&mut self, run: &SeamRunRecord) -> Result<i64, StoreError> {
        for entry in &run.entries {
            if entry.seam_id.is_empty() {
                return Err(StoreError::InvalidSeamEntry {
                    reason: "a seam has no name".to_owned(),
                });
            }
            if entry.members.is_empty() {
                return Err(StoreError::InvalidSeamEntry {
                    reason: format!("seam {:?} spans no paths", entry.seam_id),
                });
            }
            // One column holds the members, joined by newline. A glob that
            // contained one would read back as two, so it is refused here
            // rather than stored as a row that cannot be read back.
            if entry.members.iter().any(|member| member.contains('\n')) {
                return Err(StoreError::InvalidSeamEntry {
                    reason: format!("seam {:?} has a path containing a newline", entry.seam_id),
                });
            }
        }
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO seam_run
                 (root_path, settings_digest, first_commit, last_commit, commit_count,
                  scan_run_id, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                run.root_path,
                run.settings_digest,
                run.first_commit,
                run.last_commit,
                run.commit_count,
                run.scan_run_id,
                run.recorded_at,
            ],
        )?;
        let seam_run_id = tx.last_insert_rowid();
        {
            let mut statement = tx.prepare(
                "INSERT INTO seam_run_entry
                     (seam_run_id, ordinal, seam_id, members, note, asymmetric_changes,
                      breaches, last_breach, findings)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for (ordinal, entry) in run.entries.iter().enumerate() {
                statement.execute(params![
                    seam_run_id,
                    i64::try_from(ordinal).unwrap_or(i64::MAX),
                    entry.seam_id,
                    entry.members.join("\n"),
                    entry.note,
                    entry.asymmetric_changes,
                    entry.breaches,
                    entry.last_breach,
                    entry.findings,
                ])?;
            }
        }
        tx.commit()?;
        Ok(seam_run_id)
    }

    /// The newest recorded seam run for one repository root, if one exists.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn latest_seam_run(&self, root_path: &str) -> Result<Option<StoredSeamRun>, StoreError> {
        let found = self
            .conn
            .query_row(
                &format!(
                    "SELECT {SEAM_RUN_COLUMNS}
                     FROM seam_run
                     WHERE root_path = ?1
                     ORDER BY {SEAM_RUN_RECENCY}
                     LIMIT 1"
                ),
                params![root_path],
                seam_run_row,
            )
            .optional()?;
        self.with_entries(found)
    }

    /// The seam run that directly precedes `before` under the same settings.
    ///
    /// The settings digest has to agree for two runs to be two generations of
    /// one measurement: a run computed under different settings would report
    /// the settings change as a change in the code. "Precedes" is the same
    /// order [`Self::latest_seam_run`] reads, so a caller that took the latest
    /// run and asked for its predecessor never skips a generation.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn preceding_seam_run(
        &self,
        root_path: &str,
        before: i64,
        settings_digest: &str,
    ) -> Result<Option<StoredSeamRun>, StoreError> {
        let found = self
            .conn
            .query_row(
                &format!(
                    "SELECT {SEAM_RUN_COLUMNS}
                     FROM seam_run
                     WHERE root_path = ?1
                       AND settings_digest = ?3
                       AND (recorded_at, id) <
                           (SELECT recorded_at, id FROM seam_run WHERE id = ?2)
                     ORDER BY {SEAM_RUN_RECENCY}
                     LIMIT 1"
                ),
                params![root_path, before, settings_digest],
                seam_run_row,
            )
            .optional()?;
        self.with_entries(found)
    }

    /// Where every finding of one scan run sits, in a fixed order.
    ///
    /// This is the whole of what a seam mapping reads of a finding: it asks
    /// which file a finding is in and where, and deliberately reads no
    /// severity, no score and no text. A fragment the run recorded without a
    /// line reads as line zero, which is how a location with no line is
    /// spelled rather than a line of its own.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn run_finding_locations(
        &self,
        scan_run_id: i64,
    ) -> Result<Vec<FindingLocation>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT f.file_path, COALESCE(f.start_line, 0)
             FROM clone_group_member m
             JOIN fragment f ON f.id = m.fragment_id
             WHERE m.scan_run_id = ?1
             ORDER BY f.file_path ASC, COALESCE(f.start_line, 0) ASC, f.id ASC",
        )?;
        statement
            .query_map(params![scan_run_id], |row| {
                Ok(FindingLocation {
                    file_path: row.get(0)?,
                    start_line: row.get(1)?,
                })
            })?
            .collect::<Result<_, _>>()
            .map_err(StoreError::from)
    }

    /// Complete one read seam run with the entries it owns.
    fn with_entries(
        &self,
        found: Option<(i64, SeamRunRecord)>,
    ) -> Result<Option<StoredSeamRun>, StoreError> {
        let Some((id, mut run)) = found else {
            return Ok(None);
        };
        run.entries = self.seam_run_entries(id)?;
        Ok(Some(StoredSeamRun { id, run }))
    }

    /// The entries of one seam run, in the order the ledger wrote them.
    fn seam_run_entries(&self, seam_run_id: i64) -> Result<Vec<SeamEntryRecord>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT seam_id, members, note, asymmetric_changes, breaches, last_breach, findings
             FROM seam_run_entry
             WHERE seam_run_id = ?1
             ORDER BY ordinal ASC",
        )?;
        statement
            .query_map(params![seam_run_id], |row| {
                let members: String = row.get(1)?;
                Ok(SeamEntryRecord {
                    seam_id: row.get(0)?,
                    members: members.split('\n').map(str::to_owned).collect(),
                    note: row.get(2)?,
                    asymmetric_changes: row.get(3)?,
                    breaches: row.get(4)?,
                    last_breach: row.get(5)?,
                    findings: row.get(6)?,
                })
            })?
            .collect::<Result<_, _>>()
            .map_err(StoreError::from)
    }
}

/// The `seam_run` columns every read of the table selects, in the order
/// [`seam_run_row`] reads them by position.
const SEAM_RUN_COLUMNS: &str = "id, root_path, settings_digest, first_commit, last_commit, \
                                commit_count, scan_run_id, recorded_at";

/// One `seam_run` row and its id, without the entries it owns.
fn seam_run_row(row: &Row<'_>) -> rusqlite::Result<(i64, SeamRunRecord)> {
    Ok((
        row.get(0)?,
        SeamRunRecord {
            root_path: row.get(1)?,
            settings_digest: row.get(2)?,
            first_commit: row.get(3)?,
            last_commit: row.get(4)?,
            commit_count: row.get(5)?,
            scan_run_id: row.get(6)?,
            recorded_at: row.get(7)?,
            entries: Vec::new(),
        },
    ))
}
