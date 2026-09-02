//! What this build can do here, and what it found in this directory.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module exposes its diagnostics to the command layer"
)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use codehelion_core::doctor;
use codehelion_helper::client::ConfiguredHelper;
use codehelion_store::Store;

use crate::cli::DoctorArgs;
use crate::{find_git_root, is_git_ignored, resolve_db_at, scan, scan_lock};

/// How long a diagnostic waits for a helper to introduce itself.
///
/// Shorter than a scan's, because a handshake reads nothing: a helper that
/// takes longer than this to say its own name is one a person is waiting on,
/// and reporting it as unusable with the reason beats hanging the command that
/// exists to explain what is wrong.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Find a helper and ask it what it is.
///
/// Going as far as the handshake rather than stopping at the path, because a
/// program being on disk says nothing about whether this build can talk to it,
/// which compiler will answer, or what it will answer about. All three decide
/// whether a semantic run is worth starting.
///
/// The helper is shut down again. `doctor` inspects; it does not leave a
/// process running behind a command that printed a table and returned. The
/// caller supplies containment so semantic discovery and later analysis start
/// under the same policy.
///
/// `configured` carries operator authority: [`config::helper_paths`](crate::config::helper_paths) is the
/// only way a location reaches this, and it is what keeps a path written by the
/// tree under analysis from naming the program that gets started here.
pub(crate) fn interrogate(
    name: &str,
    configured: Option<&Path>,
    sandbox: codehelion_helper::SandboxRequest,
) -> Option<doctor::HelperFacts> {
    let path = codehelion_helper::locate(name, configured.map(ConfiguredHelper::operator))?;
    let state =
        match codehelion_helper::Helper::start_with_sandbox(&path, &[], HANDSHAKE_TIMEOUT, sandbox)
        {
            Ok(helper) => {
                let identity = helper.identity();
                let greeting = doctor::Greeting {
                    version: identity.version.clone(),
                    protocol: helper.protocol_version(),
                    toolchains: identity.toolchains.clone(),
                    capabilities: identity
                        .capabilities
                        .iter()
                        .map(|capability| capability.name().to_string())
                        .collect(),
                    executes: identity
                        .executes
                        .iter()
                        .map(|execution| execution.name().to_string())
                        .collect(),
                };
                // Failing to stop cleanly is not a reason to withhold what it
                // already said: the answer was given before the goodbye.
                drop(helper.shutdown());
                doctor::HelperState::Answered(greeting)
            }
            Err(error) => doctor::HelperState::Silent(format!("{error}")),
        };
    Some(doctor::HelperFacts { path, state })
}

/// Describe artifact formats this build can inspect without running them.
///
/// Kept in the composition root alongside helper discovery: format backends
/// are optional CLI capabilities and are not dependencies of the source
/// clone engine. Each line is rendered from
/// [`codehelion_artifact::FORMAT_SUPPORT`] rather than restated by hand, so a
/// format added there — or a capability changed there — shows up here without
/// a matching edit to this function.
pub(crate) fn doctor_artifacts(out: &mut impl Write) -> Result<()> {
    writeln!(out, "  artifacts:")?;
    for row in &codehelion_artifact::FORMAT_SUPPORT {
        writeln!(
            out,
            "    {}: available ({})",
            row.format.name(),
            row.capability_summary()
        )?;
    }
    Ok(())
}

/// Append the binary's install channel and location to the doctor report.
pub(crate) fn doctor_install(out: &mut impl Write) -> Result<()> {
    let exe = std::env::current_exe().context("resolving the executable path")?;
    writeln!(out)?;
    writeln!(
        out,
        "  install: {} ({})",
        install_channel(&exe),
        exe.display()
    )?;
    Ok(())
}

/// The distribution channel this binary appears to come from, inferred from
/// its on-disk location. A heuristic for diagnostics only: an unrecognised
/// location reports as a standalone install rather than failing.
pub(crate) fn install_channel(exe: &Path) -> &'static str {
    let components: Vec<String> = exe
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let has = |name: &str| components.iter().any(|c| c == name);
    if has("Cellar") || has("homebrew") || has(".linuxbrew") {
        return "homebrew";
    }
    if has(".cargo") {
        return "cargo (crates.io)";
    }
    if has("site-packages") {
        return "pypi";
    }
    // A build directory is recognised by its shape rather than by the literal
    // name `target`: `CARGO_TARGET_DIR` renames it, and the tools that wrap a
    // build pick their own name for it, so a binary under `llvm-cov-target` is
    // as local a build as one under `target`.
    let is_cargo_target = components
        .iter()
        .zip(components.iter().skip(1))
        .any(|(a, b)| a.ends_with("target") && (b == "debug" || b == "release"));
    if is_cargo_target {
        return "local build";
    }
    "standalone (archive or manual install)"
}

/// Append the local database's location to the doctor report, with a hint
/// when the database would be committed to version control.
pub(crate) fn doctor_database(args: &DoctorArgs, out: &mut impl Write) -> Result<()> {
    let cwd = codehelion_core::paths::canonical(&args.path)
        .with_context(|| format!("resolving {}", args.path.display()))?;
    // Literal on purpose: doctor reports the state of the directory, so it has
    // to name the database that was configured rather than the one another
    // command would fall back to. Which file each of them would use is the
    // next few lines' subject.
    let db = resolve_db_at(
        scan::DatabaseUse::Literal,
        &cwd,
        args.db.as_deref(),
        args.config.as_deref(),
        args.untrusted,
    )?;
    let db_abs = if db.is_absolute() {
        db.clone()
    } else {
        cwd.join(&db)
    };
    writeln!(out)?;
    match std::fs::metadata(&db_abs) {
        Ok(meta) => {
            writeln!(
                out,
                "  local database: {} ({} bytes)",
                db.display(),
                meta.len()
            )?;
            match Store::open_existing(&db_abs) {
                Ok(store) => writeln!(
                    out,
                    "  database health: schema {}, {} scan run(s), {} abandoned",
                    store.schema_version()?,
                    store.table_count("scan_run")?,
                    store.abandoned_runs()?.len()
                )?,
                Err(error) => writeln!(out, "  database health: unreadable ({error})")?,
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            writeln!(out, "  local database: {} (absent)", db.display())?;
        }
        Err(error) => {
            writeln!(
                out,
                "  local database: {} (metadata unreadable: {error})",
                db.display()
            )?;
        }
    }
    write_lease_status(&db_abs, out)?;
    doctor_database_directory(&db, &db_abs, args.db.is_some(), out)?;
    if let Some(repo_root) = find_git_root(&cwd)
        && !is_git_ignored(&repo_root, &db_abs)
    {
        writeln!(
            out,
            "  hint: the local database is not matched by .gitignore; \
                 consider ignoring it (for example, add `.codehelion/`)"
        )?;
    }
    Ok(())
}

/// Append every audit database beside the selected one, what this build can do
/// with each, and which one a scan would write.
///
/// A database written by another schema version is left exactly where it is and
/// a scan records beside it, so one directory can end up holding more than one
/// audit history. Which of them to keep is the reader's decision, and this is
/// the evidence for it.
fn doctor_database_directory(
    db: &Path,
    db_abs: &Path,
    explicit: bool,
    out: &mut impl Write,
) -> Result<()> {
    let Some(directory) = db_abs.parent() else {
        return Ok(());
    };
    let databases = audit_databases(directory, db_abs);
    if databases.is_empty() {
        return Ok(());
    }
    // The selection is made the same way a scan makes it, including the rule
    // that a named database is used as named however this build reads it.
    let replacement = if explicit {
        None
    } else {
        scan::incompatible_database_replacement(db_abs)
    };
    let recorded_into = replacement.clone().unwrap_or_else(|| db_abs.to_path_buf());
    // A reader takes a neighbour that is already there and makes none, so the
    // two answers differ exactly when the scan has not been run yet.
    let read_from = replacement
        .filter(|path| scan::readable_here(path))
        .unwrap_or_else(|| db_abs.to_path_buf());
    writeln!(
        out,
        "  databases in {}:",
        db.parent().unwrap_or(directory).display()
    )?;
    for path in &databases {
        let bytes = std::fs::metadata(path).map_or(0, |metadata| metadata.len());
        writeln!(
            out,
            "    {}: {} ({bytes} bytes)",
            path.file_name()
                .unwrap_or(path.as_os_str())
                .to_string_lossy(),
            database_readability(path),
        )?;
    }
    writeln!(
        out,
        "  a scan would use {}",
        spelled_beside(db, &recorded_into).display()
    )?;
    writeln!(
        out,
        "  a read would use {}",
        spelled_beside(db, &read_from).display()
    )?;
    // `cache clear` and `cache prune` act on the file they were pointed at, so
    // a second history in the same directory outlives them. Saying so here is
    // cheaper than discovering it after a --force.
    if databases.len() > 1 {
        writeln!(
            out,
            "  `cache clear` and `cache prune` act on the configured database alone; the other database(s) here are left as they are"
        )?;
    }
    Ok(())
}

/// `selected`, spelled the way the configured database was spelled.
///
/// The configured path is what the reader typed or read out of a
/// configuration; an absolute neighbour of it in the same line would read as
/// somewhere else.
fn spelled_beside(configured: &Path, selected: &Path) -> PathBuf {
    match (configured.parent(), selected.file_name()) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => selected.to_path_buf(),
    }
}

/// The files in `directory` that are named the way audit databases are.
///
/// Matching the selected database's extension keeps `SQLite`'s own sidecars and
/// the lease file out of a list that is about audit histories.
fn audit_databases(directory: &Path, like: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension() == like.extension())
        .collect();
    found.sort();
    found
}

/// What this build can do with one candidate audit database.
fn database_readability(path: &Path) -> String {
    match Store::open_existing(path) {
        Ok(store) => match store.schema_version() {
            Ok(version) => format!("schema {version}, readable by this build"),
            Err(error) => format!("unreadable ({error})"),
        },
        Err(codehelion_store::StoreError::UnsupportedSchema { found: 0 }) => {
            "no schema marker, not readable by this build".to_owned()
        }
        Err(codehelion_store::StoreError::UnsupportedSchema { found }) => {
            format!("schema {found}, not readable by this build")
        }
        Err(error) => format!("unreadable ({error})"),
    }
}

/// Append the point-in-time state of the database writer lease.
pub(crate) fn write_lease_status(database: &Path, out: &mut impl Write) -> Result<()> {
    match scan_lock::lease_status(database) {
        scan_lock::LeaseStatus::Available => writeln!(out, "  database lease: available")?,
        scan_lock::LeaseStatus::Held => writeln!(
            out,
            "  database lease: held by another codehelion scan or cache command"
        )?,
        scan_lock::LeaseStatus::Unreadable(error) => {
            writeln!(out, "  database lease: unreadable ({error})")?;
        }
    }
    Ok(())
}
