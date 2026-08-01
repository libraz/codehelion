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
}
