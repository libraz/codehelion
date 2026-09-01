//! Local `SQLite` storage for the current codehelion scan.
//!
//! This crate isolates the `SQLite` dependency from the analysis core: the
//! engine ([`codehelion-core`](https://docs.rs/codehelion-core)) stays free of
//! any storage backend, and the CLI drives persistence through this crate. It
//! is the canonical store; JSON, SARIF and CSV are export formats only.
//!
//! Layout:
//!
//! - [`schema`] — the current local database baseline,
//! - [`snapshot`] — the write path: one scan, one atomic transaction,
//! - [`query`] — the read path: every SQL query as a typed function,
//! - [`compiler`] — both directions for the compiler IR, whose shape is
//!   defined by the helper protocol rather than here,
//! - [`lifecycle`] — which rows survive: the one recency order, the retention
//!   contract, and the recording paths that stay safe when a measurement is
//!   taken twice,
//!
//! Opening a new database creates the current baseline. Any incompatible
//! layout is deliberately rejected; its findings should be recreated by a
//! fresh scan.

pub mod artifact;
pub mod compiler;
pub mod lifecycle;
pub mod path_key;
pub mod query;
pub mod schema;
pub mod snapshot;

mod preflight;

pub use lifecycle::{CalibrationRecord, CascadedRows, PruneReport, SelectedCloneGroupEstimate};
pub use path_key::{display_path, path_key, path_label};

use lifecycle::DatabaseKey;

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

/// Time one local connection waits for another codehelion writer to finish.
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Render a 16-byte persisted fingerprint in its canonical lowercase form.
#[must_use]
pub fn fingerprint_hex(fingerprint: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(fingerprint.len().saturating_mul(2));
    for byte in fingerprint {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

/// Return the directory component of a stored relative path.
///
/// New Windows keys use `/`, but accepting `\\` keeps rankings reproducible
/// for databases written before path-key normalization.
#[must_use]
pub fn directory_of(path: &str) -> &str {
    path.rfind(['/', '\\']).map_or("", |cut| &path[..cut])
}

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The original database or one of its relevant sidecars changed while a
    /// private preflight snapshot was being copied or validated.
    #[error(
        "database changed while it was being validated; no original database or sidecar was opened for writing, retry the operation"
    )]
    DatabaseChangedDuringPreflight,
    /// A missing or empty main database was accompanied by a `SQLite` sidecar.
    #[error(
        "database path is missing or empty but has SQLite sidecars; remove the orphaned sidecars or choose another --db path"
    )]
    OrphanedDatabaseSidecar,
    /// An I/O failure occurred while making the private validation snapshot.
    #[error("database preflight I/O error: {message}")]
    PreflightIo {
        /// The operating-system diagnostic.
        message: String,
    },
    /// An underlying database error.
    #[error("database error: {message}")]
    Sqlite {
        /// Database driver's user-facing diagnostic, retained without repeating
        /// it as an error source in a higher-level context chain.
        message: String,
    },
    /// The database is not the baseline this build supports.
    #[error(
        "database schema version {found} is not supported by this codehelion build; automatic migration is not supported and the existing database was left unchanged; move it aside or choose another --db path, then run a fresh scan"
    )]
    UnsupportedSchema {
        /// Version recorded in the database, or zero when its layout has no marker.
        found: i64,
    },
    /// A snapshot member referenced a unit index that does not exist.
    #[error("snapshot member references unit index {index}, but only {units} units were given")]
    UnknownUnitIndex {
        /// The out-of-range index.
        index: usize,
        /// Number of units in the snapshot.
        units: usize,
    },
    /// A sibling collection named no group in the same snapshot.
    #[error("snapshot sibling collection references unknown group fingerprint {fingerprint}")]
    UnknownGroupFingerprint {
        /// Hex form of the missing primary group fingerprint.
        fingerprint: String,
    },
    /// A snapshot attempted to emit two primary groups with one stable ID.
    #[error(
        "core invariant breach: duplicate clone-group fingerprint {fingerprint} reached the store"
    )]
    DuplicateGroupFingerprint {
        /// Hex form of the conflicting stable group fingerprint.
        fingerprint: String,
    },
    /// A snapshot attempted to emit two findings with one stable ID.
    #[error("core invariant breach: duplicate finding id {finding} reached the store")]
    DuplicateFindingId {
        /// Hex form of the conflicting stable finding id.
        finding: String,
    },
    /// A snapshot's compiler result named a helper that is not in the
    /// snapshot.
    #[error(
        "snapshot compiler unit references helper {index}, but only {helpers} helpers were given"
    )]
    UnknownHelperIndex {
        /// The out-of-range index.
        index: usize,
        /// Number of helpers in the snapshot.
        helpers: usize,
    },
    /// A snapshot group referenced a suppression-rule index that does not
    /// exist.
    #[error(
        "snapshot group references suppression rule {index}, but only {rules} rules were given"
    )]
    UnknownSuppressionIndex {
        /// The out-of-range index.
        index: usize,
        /// Number of rules in the snapshot.
        rules: usize,
    },
    /// A staged snapshot token did not match the suppression rows it names.
    #[error("invalid staged suppression: {reason}")]
    InvalidSuppression {
        /// Why the token cannot be trusted for atomic finalization.
        reason: String,
    },
    /// A staged finalization request was empty, duplicated, or internally
    /// inconsistent.
    #[error("invalid staged snapshot parts: {reason}")]
    InvalidSnapshotParts {
        /// Why the finalizer rejected the supplied handles.
        reason: String,
    },
    /// A caller tried to read a run before its scan invocation completed.
    #[error("scan run {run_id} did not complete and cannot be read")]
    RunNotCompleted {
        /// Row id of the incomplete run.
        run_id: i64,
    },
    /// A caller asked for a run that this database does not hold.
    #[error("scan run {run_id} was not found in this database")]
    RunNotFound {
        /// Row id of the absent run.
        run_id: i64,
    },
    /// A scan invocation tried to complete a row that was not still running.
    #[error("scan run {run_id} is not a running partition")]
    RunNotRunning {
        /// Row id of the unexpected run state.
        run_id: i64,
    },
    /// A failed multi-partition finalization could not clean up all staged
    /// rows after rolling back its primary operation.
    #[error("snapshot finalization failed: {primary}; cleanup also failed: {cleanup}")]
    AtomicFinalization {
        /// The operation that caused finalization to fail.
        primary: String,
        /// The cleanup error observed while removing staged state.
        cleanup: String,
    },
    /// An identifier string was not a 32-digit hex id.
    #[error("malformed identifier {id:?}: expected 32 hex digits")]
    MalformedId {
        /// The rejected input.
        id: String,
    },
    /// A diagnostic asked about a table that is not part of the schema.
    #[error("unknown table {table:?}")]
    UnknownTable {
        /// The rejected name.
        table: String,
    },
    /// A stored row names a classification this build does not know, which
    /// happens when a newer release wrote it. Reported rather than rounded to
    /// the nearest known value: a comparison against a guess is worse than no
    /// comparison.
    #[error("stored {field} {value:?} is not one this build understands")]
    UnknownVocabulary {
        /// Which column the value came from.
        field: &'static str,
        /// The value read.
        value: String,
    },
    /// A stored content fingerprint did not have the required 16 bytes.
    #[error("stored {field} fingerprint has {length} bytes; expected 16")]
    MalformedFingerprint {
        /// Column whose value could not represent a fingerprint.
        field: &'static str,
        /// Number of bytes the database contained.
        length: usize,
    },
    /// Mapping evidence could not establish a correspondence safely.
    #[error("invalid source-artifact mapping evidence: {reason}")]
    InvalidMappingEvidence {
        /// Why the evidence must not become a stored correspondence.
        reason: String,
    },
    /// Semantic graph evidence did not line up with the group it purports to
    /// explain, so recording it would sever the finding from its justification.
    #[error("invalid semantic evidence: {reason}")]
    InvalidSemanticEvidence {
        /// Why the evidence cannot be recorded safely.
        reason: String,
    },
    /// A requested lineage connection was not supported by the two stored runs.
    #[error("invalid clone-group lineage evidence: {reason}")]
    InvalidLineageEvidence {
        /// Why this connection cannot be committed.
        reason: String,
    },
    /// A measurement named an artifact analysis this database does not hold.
    #[error("artifact analysis {analysis_id} was not found in this database")]
    MissingArtifactAnalysis {
        /// Row id of the absent analysis.
        analysis_id: i64,
    },
    /// A full artifact IR would exceed the bounded local storage budget.
    #[error(
        "artifact analysis IR is {size_bytes} bytes, exceeding the storage limit of {maximum_bytes} bytes"
    )]
    ArtifactIrTooLarge {
        /// Serialized document size requested by the caller.
        size_bytes: usize,
        /// Largest document size the local store accepts.
        maximum_bytes: usize,
    },
    /// A persisted artifact row and its JSON document disagreed about the IR
    /// schema that defines how the document may be interpreted.
    #[error("artifact analysis IR schema is invalid: {reason}")]
    InvalidArtifactIrSchema {
        /// Why the schema contract could not be established.
        reason: String,
    },
    /// Stored mapping evidence was not valid for the version this build knows.
    #[error("invalid stored source-artifact mapping evidence: {source}")]
    MappingEvidenceJson {
        /// JSON parser error describing the malformed stored evidence.
        #[from]
        source: serde_json::Error,
    },
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite {
            message: error.to_string(),
        }
    }
}

/// An open local database at the current schema.
#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
    /// Which database this handle speaks for, so process-local state about a
    /// database follows the database rather than the handle.
    pub(crate) database: DatabaseKey,
}

/// Allocated `SQLite` pages attributed to one logical table and its indexes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableStorage {
    /// Table name from the current schema.
    pub table: String,
    /// Bytes allocated to the table and its indexes.
    pub bytes: u64,
}

impl Store {
    /// Open (creating if missing) the database at the current baseline.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnsupportedSchema`] when an incompatible layout
    /// exists at the path; otherwise any underlying database error.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        preflight::reject_orphaned_sidecars(path)?;
        let existing = std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0);
        if existing {
            // SQLite can recover a WAL or rollback journal as part of opening
            // a writer. Validate a private copy first, so an incompatible
            // database is rejected without mutating the original or its
            // sidecars.
            preflight::validate_existing(path)?;
        }
        let mut conn = if existing {
            Connection::open_with_flags(
                path,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?
        } else {
            Connection::open(path)?
        };
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // Initialize only a fresh path. Existing databases have already been
        // validated against a private copy and must be validated once more
        // after acquiring the real connection; applying the baseline here
        // would turn a race that changed the marker to zero into a mutation.
        if existing {
            schema::validate_existing(&conn)?;
        } else {
            schema::initialize(&mut conn)?;
        }
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let mut store = Self {
            conn,
            database: DatabaseKey::for_path(path),
        };
        store.discard_expired_abandoned_runs()?;
        Ok(store)
    }

    /// Open an existing database without creating or initializing a file.
    ///
    /// Read-only commands use this path so a misspelled database argument
    /// cannot leave behind an empty database that looks like scan history.
    /// The connection remains read-write because WAL readers may need `SQLite`
    /// to maintain shared-memory state; codehelion does not mutate the schema.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::UnsupportedSchema`] for an empty or incompatible
    /// database, and an underlying database error when the path is absent or
    /// unreadable.
    pub fn open_existing(path: &Path) -> Result<Self, StoreError> {
        preflight::reject_orphaned_sidecars(path)?;
        let existing = std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0);
        if existing {
            preflight::validate_existing(path)?;
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // A compatible existing database is validated again after the real
        // connection is acquired. This closes the race between private
        // preflight and the read command's SQLite connection.
        schema::validate_existing(&conn)?;
        Ok(Self {
            conn,
            database: DatabaseKey::for_path(path),
        })
    }

    /// Open a fresh in-memory database (used by tests and dry runs).
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(mut conn: Connection) -> Result<Self, StoreError> {
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        conn.pragma_update(None, "foreign_keys", true)?;
        schema::initialize(&mut conn)?;
        let mut store = Self {
            conn,
            database: DatabaseKey::in_memory(),
        };
        store.discard_expired_abandoned_runs()?;
        Ok(store)
    }

    /// The schema version of the open database.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn schema_version(&self) -> Result<i64, StoreError> {
        schema::version(&self.conn)
    }

    /// Allocated database pages grouped by logical table.
    ///
    /// Index pages are attributed to the table they index. WAL and shared-
    /// memory sidecars are file-level state and are intentionally reported by
    /// the CLI beside, rather than inside, this breakdown.
    ///
    /// # Errors
    ///
    /// Returns an underlying database error.
    pub fn table_storage(&self) -> Result<Vec<TableStorage>, StoreError> {
        let mut statement = self.conn.prepare(
            "SELECT COALESCE(m.tbl_name, d.name) AS logical_table, SUM(d.pgsize)
             FROM dbstat d
             LEFT JOIN sqlite_master m ON m.name = d.name
             WHERE d.name NOT LIKE 'sqlite_%'
             GROUP BY logical_table
             ORDER BY SUM(d.pgsize) DESC, logical_table ASC",
        )?;
        let rows = statement
            .query_map([], |row| {
                let bytes = row.get::<_, i64>(1)?;
                Ok(TableStorage {
                    table: row.get(0)?,
                    bytes: u64::try_from(bytes).unwrap_or(0),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn directory_of_accepts_both_stored_path_separators() {
        assert_eq!(directory_of("source.rs"), "");
        assert_eq!(directory_of("src/nested/source.rs"), "src/nested");
        assert_eq!(directory_of("src\\nested\\source.rs"), "src\\nested");
    }

    #[test]
    fn an_in_memory_store_uses_the_current_baseline() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION);
    }

    #[test]
    fn file_backed_stores_use_wal_and_wait_for_a_concurrent_writer() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let store = Store::open(file.path()).unwrap();
        let journal_mode: String = store
            .conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        let busy_timeout_ms: i64 = store
            .conn
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .unwrap();

        assert_eq!(journal_mode, "wal");
        assert_eq!(busy_timeout_ms, 5_000);
    }

    #[test]
    fn file_open_waits_for_the_lock_needed_to_confirm_wal_mode() {
        use std::sync::mpsc;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        let store = Store::open(&path).unwrap();
        store.conn.execute_batch("BEGIN EXCLUSIVE").unwrap();

        let (started_tx, started_rx) = mpsc::channel();
        let path_for_thread = path;
        let opener = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            Store::open(&path_for_thread).map(drop)
        });
        started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        store.conn.execute_batch("COMMIT").unwrap();

        opener.join().unwrap().unwrap();
    }

    #[test]
    fn existing_open_does_not_initialize_an_empty_file() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let error = Store::open_existing(file.path()).unwrap_err();

        assert!(matches!(error, StoreError::UnsupportedSchema { found: 0 }));
        assert_eq!(std::fs::metadata(file.path()).unwrap().len(), 0);
    }

    #[test]
    fn table_storage_attributes_index_pages_to_their_tables() {
        let store = Store::open_in_memory().unwrap();
        let storage = store.table_storage().unwrap();

        assert!(
            storage
                .iter()
                .any(|entry| entry.table == "scan_run" && entry.bytes > 0)
        );
        assert!(storage.iter().all(|entry| !entry.table.starts_with("idx_")));
    }

    #[test]
    fn fingerprint_hex_is_lowercase_and_fixed_width() {
        assert_eq!(fingerprint_hex([0xab; 16]), "ab".repeat(16));
    }

    #[test]
    fn duplicate_identity_errors_are_explicit_core_invariant_breaches() {
        let group_fingerprint = "0123456789abcdef0123456789abcdef";
        let finding_id = "fedcba9876543210fedcba9876543210";

        assert_eq!(
            StoreError::DuplicateGroupFingerprint {
                fingerprint: group_fingerprint.to_string(),
            }
            .to_string(),
            format!(
                "core invariant breach: duplicate clone-group fingerprint {group_fingerprint} \
                 reached the store"
            )
        );
        assert_eq!(
            StoreError::DuplicateFindingId {
                finding: finding_id.to_string(),
            }
            .to_string(),
            format!("core invariant breach: duplicate finding id {finding_id} reached the store")
        );
    }

    #[test]
    fn user_facing_storage_errors_do_not_repeat_causes_or_internal_labels() {
        let error = StoreError::UnsupportedSchema { found: 99 }.to_string();
        assert!(error.contains("not supported by this codehelion build"));
        assert!(!error.contains("pre-release"));
        assert!(!error.contains("development database"));

        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not an sqlite database").unwrap();
        let error = Store::open(file.path()).unwrap_err().to_string();
        assert_eq!(error.matches("file is not a database").count(), 1);
    }

    #[test]
    fn every_current_scan_entity_table_exists() {
        let store = Store::open_in_memory().unwrap();
        for table in [
            "scan_run",
            "build_variant",
            "build_variant_setting",
            "source_unit",
            "fragment",
            "fingerprint",
            "clone_group",
            "finding",
            "suppression",
            "artifact",
            "artifact_symbol",
            "artifact_analysis",
            "artifact_analysis_symbol",
            "artifact_analysis_source_mapping",
            "artifact_analysis_unmapped_symbol",
            "artifact_analysis_unmapped_source",
            "artifact_analysis_correlation",
            "source_artifact_mapping",
            "detector_version",
            "clone_group_similarity",
            "compiler_helper",
            "compiler_unit",
            "compiler_type",
            "compiler_symbol",
            "compiler_call",
            "compiler_block",
            "compiler_edge",
            "compiler_instantiation",
            "compiler_effect",
            "compiler_data_flow",
            "cross_variant_comparison",
            "cross_variant_comparison_origin",
            "cross_variant_clone_group",
            "cross_variant_clone_member",
            "semantic_operation_graph",
            "semantic_group_evidence",
            "semantic_node_mapping",
        ] {
            let count: i64 = store
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "missing table {table}");
        }
    }
}
