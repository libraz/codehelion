//! Read-only validation of an existing database and its `SQLite` sidecars.
//!
//! `SQLite` may recover a WAL or journal when a read-write connection is opened.
//! That is the right behavior for a healthy database, but it is not safe as the
//! first step when an incompatible schema must be rejected without changing
//! the user's files.  This module validates a private copy instead.  The
//! original files are fingerprinted around the copy and validation so a
//! concurrent writer cannot turn the private result into a claim about a
//! different database state.

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

/// A stable fingerprint of one database member at one point in time.
#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    exists: bool,
    len: u64,
    digest: [u8; 32],
}

/// Validate an existing database without opening the original path.
pub(super) fn validate_existing(path: &Path) -> Result<(), StoreError> {
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
