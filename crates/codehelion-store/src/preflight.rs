//! Read-only validation of an existing database and its `SQLite` sidecars.
//!
//! `SQLite` may recover a WAL or journal when a read-write connection is opened.
//! That is the right behavior for a healthy database, but it is not safe as the
//! first step when an incompatible schema must be rejected without changing
//! the user's files.
//!
//! A read-only connection cannot recover either sidecar, so a database `SQLite`
//! will open that way is validated where it lies: the answer costs the few
//! pages the schema marker sits on, whatever the database weighs, and a
//! concurrent writer is something the connection waits for rather than races.
//! Only a database that cannot be read that way — a left-behind hot journal is
//! the usual reason — falls back to validating a private copy, with the
//! original files fingerprinted around the copy and the validation so that a
//! writer cannot turn the private result into a claim about a different
//! database state.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the private preflight module exposes orchestration helpers only to its parent store module"
)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use crate::{StoreError, schema};

/// The number of attempts allowed when a database changes during validation.
const MAX_ATTEMPTS: usize = 3;

/// The sidecars whose bytes can affect `SQLite`'s logical database state before
/// the original connection is opened.  Shared memory is deliberately omitted:
/// the private `SQLite` connection creates its own private shared-memory file.
const SNAPSHOT_SIDECARS: &[&str] = &["-wal", "-journal"];

/// Time one private validation connection waits for a writer to finish.
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

// Databases validated by copying them, so that a test can hold the in-place
// path to its promise that a healthy database is never copied to be read.
// Counted per thread, which is per test: a shared count would be a running
// total of whatever else the suite was doing at the same moment.
#[cfg(test)]
thread_local! {
    static PRIVATE_COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Note that a database is about to be validated through a private copy.
#[cfg(test)]
fn record_private_copy() {
    PRIVATE_COPIES.with(|copies| copies.set(copies.get().saturating_add(1)));
}

/// How many databases this thread has validated by copying them.
#[cfg(test)]
fn private_copies() -> usize {
    PRIVATE_COPIES.with(std::cell::Cell::get)
}

/// Note that a database is about to be validated through a private copy.
#[cfg(not(test))]
const fn record_private_copy() {}

/// A stable fingerprint of one database member at one point in time.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    exists: bool,
    len: u64,
    digest: [u8; 32],
}

/// Validate an existing database without writing to it.
pub(super) fn validate_existing(path: &Path) -> Result<(), StoreError> {
    match validate_in_place(path) {
        // A schema this build does not support is a complete answer, and
        // reaching it read-only is the whole point: nothing was recovered,
        // checkpointed or copied to find it out.
        result @ (Ok(()) | Err(StoreError::UnsupportedSchema { .. })) => result,
        // Anything else means the database could not be read this way, which a
        // private copy can still settle.
        Err(_) => validate_private_copy(path),
    }
}

/// Read the schema marker over a connection that cannot alter anything.
///
/// The connection is read-only, so `SQLite` will not recover a WAL or a
/// rollback journal to serve it: a database in either state fails here instead
/// of being repaired behind the user's back.
fn validate_in_place(path: &Path) -> Result<(), StoreError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
    schema::validate_existing(&conn)
}

/// Validate a private copy of the database and its sidecars.
fn validate_private_copy(path: &Path) -> Result<(), StoreError> {
    record_private_copy();
    for _attempt in 0..MAX_ATTEMPTS {
        let before = stamp_members(path)?;
        let snapshot = tempfile::tempdir().map_err(|error| io_error(&error))?;
        let snapshot_path = snapshot_path(snapshot.path(), path);

        copy_snapshot_members(path, &snapshot_path)?;
        let after_copy = stamp_members(path)?;
        if before != after_copy {
            continue;
        }

        let result = validate_snapshot(&snapshot_path);
        let after_validation = stamp_members(path)?;
        if before != after_validation {
            continue;
        }

        return result;
    }

    Err(StoreError::DatabaseChangedDuringPreflight)
}

/// Reject a zero-length or missing main file when `SQLite` sidecars are left
/// behind.  A zero-length database without sidecars is still a valid fresh
/// target and is initialized by the normal open path.
pub(super) fn reject_orphaned_sidecars(path: &Path) -> Result<(), StoreError> {
    let main_is_empty = fs::metadata(path).map_or(true, |metadata| metadata.len() == 0);
    if !main_is_empty {
        return Ok(());
    }

    let has_sidecar = sidecar_paths(path)
        .iter()
        .any(|sidecar| fs::metadata(sidecar).is_ok());
    if has_sidecar {
        return Err(StoreError::OrphanedDatabaseSidecar);
    }
    Ok(())
}

/// Construct a sidecar path without assuming that the database path is UTF-8.
fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn sidecar_paths(path: &Path) -> [PathBuf; 3] {
    [
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-journal"),
        sidecar_path(path, "-shm"),
    ]
}

fn snapshot_path(directory: &Path, original: &Path) -> PathBuf {
    let name = original
        .file_name()
        .unwrap_or_else(|| OsStr::new("database"));
    directory.join(name)
}

fn stamp_members(path: &Path) -> Result<Vec<(String, FileStamp)>, StoreError> {
    let mut members = Vec::with_capacity(1 + SNAPSHOT_SIDECARS.len());
    members.push(("main".to_string(), stamp(path)?));
    for suffix in SNAPSHOT_SIDECARS {
        members.push(((*suffix).to_string(), stamp(&sidecar_path(path, suffix))?));
    }
    Ok(members)
}

fn stamp(path: &Path) -> Result<FileStamp, StoreError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(FileStamp {
                exists: false,
                len: 0,
                digest: [0; 32],
            });
        }
        Err(error) => return Err(io_error(&error)),
    };
    let mut hasher = blake3::Hasher::new();
    let mut len = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| io_error(&error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        len = len
            .checked_add(u64::try_from(read).map_err(|_| StoreError::PreflightIo {
                message: "file length exceeded u64::MAX during preflight".to_string(),
            })?)
            .ok_or_else(|| StoreError::PreflightIo {
                message: "file length exceeded u64::MAX during preflight".to_string(),
            })?;
    }
    Ok(FileStamp {
        exists: true,
        len,
        digest: *hasher.finalize().as_bytes(),
    })
}

fn copy_snapshot_members(original: &Path, snapshot: &Path) -> Result<(), StoreError> {
    copy_one(original, snapshot)?;
    for suffix in SNAPSHOT_SIDECARS {
        let source = sidecar_path(original, suffix);
        if stamp(&source)?.exists {
            copy_one(&source, &sidecar_path(snapshot, suffix))?;
        }
    }
    Ok(())
}

fn copy_one(source: &Path, destination: &Path) -> Result<(), StoreError> {
    let mut source_file = match File::open(source) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(StoreError::DatabaseChangedDuringPreflight);
        }
        Err(error) => return Err(io_error(&error)),
    };
    let mut destination_file = File::create(destination).map_err(|error| io_error(&error))?;
    std::io::copy(&mut source_file, &mut destination_file).map_err(|error| io_error(&error))?;
    destination_file.flush().map_err(|error| io_error(&error))
}

fn validate_snapshot(path: &Path) -> Result<(), StoreError> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
    conn.pragma_update(None, "foreign_keys", true)?;
    schema::validate_existing(&conn)
}

fn io_error(error: &std::io::Error) -> StoreError {
    StoreError::PreflightIo {
        message: error.to_string(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A database at the current baseline, with rows enough to have pages.
    fn populated(path: &Path) {
        let store = crate::Store::open(path).expect("a fresh database opens");
        store
            .conn
            .execute_batch(
                "CREATE TABLE weight (id INTEGER PRIMARY KEY, body TEXT);
                 INSERT INTO weight (body)
                 WITH RECURSIVE many(n) AS (
                     SELECT 1 UNION ALL SELECT n + 1 FROM many WHERE n < 2000
                 )
                 SELECT hex(randomblob(256)) FROM many;",
            )
            .expect("the rows are written");
    }

    #[test]
    fn a_healthy_database_is_read_where_it_lies_rather_than_copied() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        populated(&path);

        let copies_before = private_copies();
        for _ in 0..8 {
            validate_existing(&path).expect("the baseline is the one this build writes");
        }

        assert_eq!(
            private_copies(),
            copies_before,
            "a database was copied to be read"
        );
    }

    #[test]
    fn a_schema_this_build_does_not_know_is_refused_without_copying_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        populated(&path);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute("UPDATE schema_meta SET version = 9999 WHERE id = 1", [])
                .unwrap();
        }

        let copies_before = private_copies();
        let error = validate_existing(&path).expect_err("the version is not this build's");

        assert!(
            matches!(error, StoreError::UnsupportedSchema { found: 9999 }),
            "{error:?}"
        );
        assert_eq!(private_copies(), copies_before);
    }

    #[test]
    fn validating_recovers_nothing_into_the_database_or_its_sidecars() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        populated(&path);
        let before = stamp(&path).unwrap();

        validate_existing(&path).expect("the baseline is the one this build writes");

        assert_eq!(stamp(&path).unwrap(), before, "the database was written to");
        for suffix in SNAPSHOT_SIDECARS {
            // Opening a database that was left in write-ahead mode re-creates
            // the empty write-ahead file that closing it removed. What must
            // not appear is content: a byte in either sidecar would mean
            // something was recovered or checkpointed to answer a question.
            let sidecar = stamp(&sidecar_path(&path, suffix)).unwrap();
            assert_eq!(sidecar.len, 0, "{suffix} carries content after validating");
        }
    }

    #[test]
    fn a_database_a_writer_keeps_changing_is_still_validated() {
        use std::sync::mpsc;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.db");
        populated(&path);

        let (stop, stopped) = mpsc::channel::<()>();
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            let conn = Connection::open(&writer_path).expect("the writer opens it");
            conn.busy_timeout(SQLITE_BUSY_TIMEOUT).unwrap();
            while stopped.try_recv() == Err(mpsc::TryRecvError::Empty) {
                conn.execute(
                    "INSERT INTO weight (body) VALUES (hex(randomblob(256)))",
                    [],
                )
                .expect("the writer keeps writing");
            }
        });

        for _ in 0..20 {
            validate_existing(&path).expect("a busy writer does not make a database unreadable");
        }

        drop(stop);
        writer.join().expect("the writer finishes");
    }
}
