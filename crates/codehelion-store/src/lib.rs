//! Local `SQLite` audit storage for codehelion.
//!
//! This crate isolates the `SQLite` dependency from the analysis core: the
//! engine ([`codehelion-core`](https://docs.rs/codehelion-core)) stays free of
//! any storage backend, and the CLI drives persistence through this crate. It
//! is the canonical store; JSON, SARIF and CSV are export formats only.
//!
//! Layout:
//!
//! - [`schema`] — the DDL and the forward-only migration mechanism,
//! - [`snapshot`] — the write path: one scan, one atomic transaction,
//! - [`query`] — the read path: every SQL query as a typed function,
//! - [`compiler`] — both directions for the compiler IR, whose shape is
//!   defined by the helper protocol rather than here,
//! - [`migrate`] — rewriting recorded history when the rules that make
//!   identifiers change under it.
//!
//! Opening a database migrates it forward when it is older and refuses it
//! when it is newer than this build supports; downgrade is unsupported by
//! design.

pub mod compiler;
pub mod migrate;
pub mod query;
pub mod schema;
pub mod snapshot;

use std::path::Path;

use rusqlite::Connection;

/// Storage errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// An underlying database error.
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// The database was written by a newer tool version.
    #[error(
        "database schema version {found} is newer than this build supports \
         ({supported}); upgrade codehelion (downgrading a database is not supported)"
    )]
    SchemaTooNew {
        /// Version recorded in the database.
        found: i64,
        /// Newest version this build understands.
        supported: i64,
    },
    /// Migrating left a reference pointing at a row that is not there.
    ///
    /// Foreign keys are not enforced while migrations run, because rebuilding
    /// a table under enforcement destroys everything that cascades off it.
    /// This is the check that replaces the enforcement, and it fires before
    /// the database is handed back rather than at the next write.
    #[error("migrating left {rows} reference(s) pointing at rows that are not there")]
    MigrationOrphanedRows {
        /// How many references `foreign_key_check` reported.
        rows: i64,
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
}

/// An open audit database, migrated to the current schema.
#[derive(Debug)]
pub struct Store {
    pub(crate) conn: Connection,
}

impl Store {
    /// Open (creating if missing) the database at `path` and migrate it to
    /// the current schema.
    ///
    /// # Errors
    ///
    /// [`StoreError::SchemaTooNew`] when the database was written by a newer
    /// tool; otherwise any underlying database error.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open(path)?)
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
        conn.pragma_update(None, "foreign_keys", true)?;
        schema::migrate(&mut conn)?;
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
    fn an_in_memory_store_migrates_to_the_current_version() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION);
    }

    #[test]
    fn every_audit_entity_table_exists() {
        let store = Store::open_in_memory().unwrap();
        for table in [
            "scan_run",
            "build_variant",
            "build_variant_setting",
            "source_unit",
            "fragment",
            "fingerprint",
            "clone_group",
            "group_lineage",
            "finding",
            "suppression",
            "artifact",
            "artifact_symbol",
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
