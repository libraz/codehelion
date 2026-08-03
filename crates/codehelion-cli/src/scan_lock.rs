//! Cross-process coordination for scan persistence and cache deletion.
//!
//! A scan does most of its work before it writes `SQLite`. Holding only a
//! database transaction therefore cannot stop `cache clear` from unlinking
//! the database while that work is underway. This small sidecar lock spans
//! the whole command instead, so a clear either happens before a scan starts
//! or after it has durably recorded its result.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt;

/// An exclusive lease for one audit database.
#[derive(Debug)]
pub struct DatabaseLock {
    file: File,
}

/// What a non-mutating probe found for one database lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseStatus {
    /// No process currently holds the lease.
    Available,
    /// Another process currently holds the lease.
    Held,
    /// The lease sidecar could not be inspected.
    Unreadable(String),
}

impl Drop for DatabaseLock {
    fn drop(&mut self) {
        // A failed unlock cannot be recovered during destruction. Closing the
        // descriptor also releases the OS-level advisory lock.
        let _ = FileExt::unlock(&self.file);
    }
}

/// Acquire the database's non-blocking advisory lock.
///
/// The sidecar is intentionally retained after a command finishes: deleting
/// a lock pathname after releasing it would let a second process create a new
/// inode while another process still holds the old one.
///
/// # Errors
///
/// Returns an error when another scan or cache clear already owns the lease,
/// or when the lock's parent directory or sidecar cannot be opened.
pub fn acquire(database: &Path) -> Result<DatabaseLock> {
    if let Some(parent) = database.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating database lock directory {}", parent.display()))?;
    }
    let lock_path = lock_path(database);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening database lock {}", lock_path.display()))?;
    if let Err(error) = FileExt::try_lock_exclusive(&file) {
        bail!(
            "database {} is in use by another codehelion scan or cache clear: {error}",
            database.display()
        );
    }
    Ok(DatabaseLock { file })
}

/// Inspect a database lease without creating its sidecar or retaining a lock.
///
/// # Safety of the result
///
/// The result is a point-in-time diagnostic. A writer can acquire the lease
/// immediately after this function returns, so callers must still call
/// [`acquire`] before any mutation.
#[must_use]
pub fn lease_status(database: &Path) -> LeaseStatus {
    let path = lock_path(database);
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LeaseStatus::Available;
        }
        Err(error) => return LeaseStatus::Unreadable(error.to_string()),
    };
    match FileExt::try_lock_exclusive(&file) {
        Ok(()) => {
            // Closing the descriptor releases the advisory lock even if an
            // explicit unlock reports an OS error, so this probe never holds
            // the lease past its return.
            drop(FileExt::unlock(&file));
            LeaseStatus::Available
        }
        Err(error) if is_contention(&error) => LeaseStatus::Held,
        Err(error) => LeaseStatus::Unreadable(error.to_string()),
    }
}

/// Whether a refused lock attempt means somebody else holds the lease.
///
/// Contention is not one error. A system that refuses an immediate lock
/// reports it in its own terms, and only one of those terms is the
/// would-block reading: Windows calls it a lock violation, which carries no
/// portable kind and would otherwise be read as a sidecar nobody can inspect.
/// The locking library states which error its own attempt produces under
/// contention, so ask it rather than enumerate the systems.
fn is_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

/// Stable sidecar path used by all commands that coordinate one database.
#[must_use]
fn lock_path(database: &Path) -> PathBuf {
    let mut path: OsString = database.as_os_str().to_owned();
    path.push(".lock");
    PathBuf::from(path)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn one_database_has_one_exclusive_lease() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("audit.db");
        let first = acquire(&database).unwrap();
        let error = acquire(&database).expect_err("second lease must be refused");
        assert!(
            error
                .to_string()
                .contains("another codehelion scan or cache clear")
        );
        drop(first);
        acquire(&database).expect("released lease can be acquired again");
    }

    /// The probe reads a refused lock the way the locking library reports it.
    ///
    /// Stated here as well as in the probe, because a system whose refusal
    /// carries a different spelling turns a held lease into an unreadable one,
    /// and the probe alone only says so where that system runs.
    #[test]
    fn a_refused_immediate_lock_reads_as_contention() {
        assert!(is_contention(&fs2::lock_contended_error()));
        assert!(!is_contention(&std::io::Error::from(
            std::io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn a_status_probe_reports_a_live_lease_without_retaining_one() {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("audit.db");
        assert_eq!(lease_status(&database), LeaseStatus::Available);
        let held = acquire(&database).unwrap();
        assert_eq!(lease_status(&database), LeaseStatus::Held);
        drop(held);
        assert_eq!(lease_status(&database), LeaseStatus::Available);
    }
}
