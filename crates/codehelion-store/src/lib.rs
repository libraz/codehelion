//! Local `SQLite` storage for the current codehelion scan.
//!
//! This crate isolates the `SQLite` dependency from the analysis core: the
//! engine ([`codehelion-core`](https://docs.rs/codehelion-core)) stays free of
//! any storage backend, and the CLI drives persistence through this crate. It
//! is the canonical store; JSON, SARIF and CSV are export formats only.
//!
//! Layout:
//!
//! - [`schema`] — the single pre-release database baseline,
//! - [`snapshot`] — the write path: one scan, one atomic transaction,
//! - [`query`] — the read path: every SQL query as a typed function,
//! - [`compiler`] — both directions for the compiler IR, whose shape is
//!   defined by the helper protocol rather than here,
//!
//! Before release, opening a new database creates the current baseline.
//! Any earlier development layout is deliberately rejected; its findings
//! should be recreated by a fresh scan.

pub mod artifact;
pub mod compiler;
pub mod query;
pub mod schema;
pub mod snapshot;

use std::path::Path;
use std::time::Duration;

use rusqlite::Connection;

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

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An underlying database error.
    #[error("database error: {message}")]
    Sqlite {
        /// Database driver's user-facing diagnostic, retained without repeating
        /// it as an error source in a higher-level context chain.
        message: String,
    },
    /// The database is not the baseline this build supports.
    #[error(
        "database schema version {found} is not supported by this codehelion build; \
         move the database aside, then run a fresh scan"
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
}

impl Store {
    /// Open (creating if missing) the database at the current baseline.
    ///
    /// # Errors
    ///
    /// [`StoreError::UnsupportedSchema`] when an incompatible layout
    /// exists at the path; otherwise any underlying database error.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Self::from_connection(conn)
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
        Ok(Self { conn })
    }

    /// The schema version of the open database.
    ///
    /// # Errors
    ///
    /// Returns any underlying database error.
    pub fn schema_version(&self) -> Result<i64, StoreError> {
        schema::version(&self.conn)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

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
    fn fingerprint_hex_is_lowercase_and_fixed_width() {
        assert_eq!(fingerprint_hex([0xab; 16]), "ab".repeat(16));
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
            "feature_fingerprint",
            "feature_occurrence",
            "unit_feature",
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
