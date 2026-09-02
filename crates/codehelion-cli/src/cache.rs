//! Inspecting, pruning and clearing the local audit database.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module exposes the cache actions to the command layer"
)]

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use codehelion_store::Store;

use crate::cli::CacheAction;
use crate::doctor_command::write_lease_status;
use crate::{Outcome, resolve_db_at, scan, scan_lock};

/// The database one `cache` action works on.
///
/// The three actions resolve it the same way and differ only in what they are
/// allowed to do about a default this build cannot open; see
/// [`scan::DatabaseUse`].
fn cache_database(
    intent: scan::DatabaseUse,
    path: &Path,
    db: Option<&Path>,
    config: Option<&Path>,
    untrusted: bool,
) -> Result<PathBuf> {
    resolve_db_at(intent, path, db, config, untrusted)
}

pub(crate) fn cache_command(action: &CacheAction, out: &mut impl Write) -> Result<Outcome> {
    match action {
        CacheAction::Status {
            path,
            config,
            db,
            untrusted,
        } => cache_status(
            &cache_database(
                scan::DatabaseUse::Reading,
                path,
                db.as_deref(),
                config.as_deref(),
                *untrusted,
            )?,
            out,
        ),
        CacheAction::Prune {
            path,
            config,
            db,
            untrusted,
            keep_artifacts,
            keep_comparisons,
            force,
        } => {
            if !force {
                bail!("`cache prune` deletes retained local history; pass --force to confirm");
            }
            // Literal: a command that deletes acts on the file it was pointed
            // at, whatever this build can make of it.
            cache_prune(
                &cache_database(
                    scan::DatabaseUse::Literal,
                    path,
                    db.as_deref(),
                    config.as_deref(),
                    *untrusted,
                )?,
                *keep_artifacts,
                *keep_comparisons,
                out,
            )
        }
        CacheAction::Clear {
            path,
            config,
            db,
            untrusted,
            force,
        } => {
            if !force {
                bail!(
                    "`cache clear` permanently deletes the local audit database; pass --force to confirm"
                );
            }
            cache_clear(
                &cache_database(
                    scan::DatabaseUse::Literal,
                    path,
                    db.as_deref(),
                    config.as_deref(),
                    *untrusted,
                )?,
                out,
            )
        }
    }
}

/// Report where the local database is, what this build makes of it, and
/// whether anything holds its lease.
fn cache_status(path: &Path, out: &mut impl Write) -> Result<Outcome> {
    let files = database_files(path);
    if let Some(size) = database_storage_bytes(&files)? {
        writeln!(out, "database: {} ({} bytes)", path.display(), size)?;
        match Store::open_existing(path) {
            Ok(store) => {
                writeln!(out, "schema: {}", store.schema_version()?)?;
                writeln!(out, "scan runs: {}", store.table_count("scan_run")?)?;
                let unfinished = store.abandoned_runs()?.len();
                // A `running` row is abandoned only once nothing owns it. The
                // reaper this diagnostic sits beside applies a grace period
                // before it treats one as abandoned (see
                // `discard_expired_abandoned_runs`); this line has to make the
                // same distinction rather than calling every `running` row
                // abandoned, or it steers the reader toward `cache prune`
                // while a scan is still writing.
                if unfinished > 0 && scan_lock::lease_status(path) == scan_lock::LeaseStatus::Held {
                    writeln!(
                        out,
                        "incomplete partitions: {unfinished} (a scan is running)"
                    )?;
                } else {
                    writeln!(out, "abandoned runs: {unfinished}")?;
                }
                writeln!(out, "table storage:")?;
                for table in store.table_storage()? {
                    writeln!(out, "  {}: {} bytes", table.table, table.bytes)?;
                }
            }
            Err(error) => writeln!(out, "database health: unreadable ({error})")?,
        }
    } else {
        writeln!(out, "database: {} (absent)", path.display())?;
    }
    write_lease_status(path, out)?;
    Ok(Outcome::Success)
}

/// Drop the retained history the flags do not ask to keep.
fn cache_prune(
    path: &Path,
    keep_artifacts: usize,
    keep_comparisons: usize,
    out: &mut impl Write,
) -> Result<Outcome> {
    if !path.is_file() {
        bail!(
            "no local database at {}; run `codehelion scan` first",
            path.display()
        );
    }
    let _lock = scan_lock::acquire(path)?;
    let mut store = Store::open_existing(path)
        .with_context(|| format!("opening audit database {}", path.display()))?;
    let pruned = store.prune(keep_artifacts, keep_comparisons)?;
    writeln!(
        out,
        "pruned {} abandoned run(s), {} artifact analysis(es), {} cross-variant comparison(s), {} cross-language comparison(s), and {} orphaned fingerprint(s)",
        pruned.abandoned_runs,
        pruned.artifact_analyses,
        pruned.cross_variant_comparisons,
        pruned.cross_language_comparisons,
        pruned.orphaned_fingerprints
    )?;
    // The five named counts are what the retention flags asked for. A removed
    // row takes referencing rows with it, and those live in tables nobody
    // named — the verified-savings ledger among them, which the reader was
    // told is kept. Left unsaid, a later statistic taken over that ledger
    // moves with no visible cause, so the whole deletion is reported and not
    // just the part that was requested.
    for cascaded in &pruned.cascaded {
        writeln!(
            out,
            "  also removed {} row(s) from {} that referenced them",
            cascaded.rows, cascaded.table
        )?;
    }
    Ok(Outcome::Success)
}

/// Remove the named database and the sidecars WAL mode created beside it.
fn cache_clear(path: &Path, out: &mut impl Write) -> Result<Outcome> {
    if !database_files(path).iter().any(|file| file.exists()) {
        writeln!(out, "nothing to remove at {}", path.display())?;
        return Ok(Outcome::Success);
    }
    let _lock = scan_lock::acquire(path)?;
    let removed = database_files(path)
        .iter()
        .map(|file| remove_database_file(file))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|removed| *removed)
        .count();
    if removed > 0 {
        writeln!(out, "removed {}", path.display())?;
    } else {
        writeln!(out, "nothing to remove at {}", path.display())?;
    }
    Ok(Outcome::Success)
}

/// The main `SQLite` database and the sidecars a rollback journal or WAL mode
/// can leave beside it.
///
/// `-journal` belongs here alongside `-wal`/`-shm`: schema initialization on a
/// brand-new database runs under the default rollback journal before WAL mode
/// takes over, so a run interrupted early enough leaves `-journal` rather than
/// `-wal`/`-shm`. `codehelion-store` treats all three as sidecars of the same
/// database (see its own `sidecar_paths`); this list must keep matching that
/// one so `cache clear` never leaves a file behind that a later `Store::open`
/// refuses to open.
pub(crate) fn database_files(database: &Path) -> [PathBuf; 4] {
    [
        database.to_path_buf(),
        database_sidecar_path(database, "-wal"),
        database_sidecar_path(database, "-journal"),
        database_sidecar_path(database, "-shm"),
    ]
}

/// Sum the main database and WAL sidecars, distinguishing absent files from
/// metadata failures that deserve to reach the caller.
pub(crate) fn database_storage_bytes(files: &[PathBuf; 4]) -> Result<Option<u64>> {
    let mut size = 0_u64;
    let mut present = false;
    for file in files {
        match std::fs::metadata(file) {
            Ok(metadata) => {
                present = true;
                size = size.saturating_add(metadata.len());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading database metadata {}", file.display()));
            }
        }
    }
    Ok(present.then_some(size))
}

fn database_sidecar_path(database: &Path, suffix: &str) -> PathBuf {
    let mut sidecar: OsString = database.as_os_str().to_owned();
    sidecar.push(suffix);
    PathBuf::from(sidecar)
}

/// Remove one database file, allowing an absent WAL sidecar.
fn remove_database_file(path: &Path) -> Result<bool> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}
