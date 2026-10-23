//! Database path resolution and confinement.

#![allow(
    clippy::redundant_pub_crate,
    reason = "database helpers are crate-visible so scan submodules can share one resolver"
)]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::config::{ResolvedConfig, configured_paths};
use crate::provenance::{Authority, FromScannedTree, OperatorSupplied};

/// What a command does with the audit database it names, which decides
/// whether it may step around a default one this build cannot open.
///
/// One rule, three answers, because the same step aside is right for a
/// command that records, half right for one that reads, and wrong for one
/// that describes what was configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatabaseUse {
    /// The command records: it may write beside an unreadable default, making
    /// the neighbour if it is not there yet.
    Recording,
    /// The command reads: it opens a neighbour that already exists, and never
    /// makes one. A missing neighbour leaves the default's own error, so
    /// "nothing has been scanned yet" stays distinguishable from "the scan
    /// went somewhere else".
    Reading,
    /// The command reports on the file that was configured, before any
    /// stepping aside: `doctor` describing the directory, or a hint about the
    /// directory the database lives in.
    Literal,
}

/// Resolve the audit database one command uses, stepping around a default
/// database this build cannot open when that command's job allows it.
///
/// Every command that opens the audit database resolves it here, so that the
/// reader who followed a note printed by one of them arrives at the same file.
/// A scan that records beside an unreadable default and a report that then
/// opens the default is one tool disagreeing with itself. The choice itself is
/// [`DatabaseLocation::select`]; this prints the note it owes.
///
/// # Errors
///
/// Returns an actionable error when a repository-controlled configuration
/// names an absolute, traversing, or symlink-escaping database path, on the
/// configured path or on any file that stands in for it.
pub(crate) fn database_path_for(
    intent: DatabaseUse,
    root: &Path,
    flag: Option<&Path>,
    config: &ResolvedConfig,
    untrusted: bool,
) -> Result<PathBuf> {
    Ok(database_location(root, flag, config, untrusted)?
        .select(intent)?
        .announced())
}

/// Where the configured audit database is, and the boundary every file that
/// may stand in for it is held to.
///
/// `--db` is an explicit operator instruction and may name storage outside the
/// scan; a relative one is read against the working directory, and it is never
/// traded for another file, whatever the job. A database setting from a
/// configuration found at the scan root is not an operator instruction: it is
/// confined to `--path`, including its existing symlink components.
/// `--untrusted` applies that confinement to any configured path, even one
/// from an explicitly named configuration file.
///
/// The boundary is `--path` and not the repository holding it, because
/// `--path` is the only directory the operator pointed at. A repository root
/// is found by looking for a `.git` ancestor, so for the case `--untrusted`
/// exists for — auditing a vendored subtree of one's own worktree — it sits
/// above what was selected, and a configuration inside that subtree would be
/// choosing storage among its siblings. `root` is expected canonical, which is
/// what every caller resolves before calling. Where a database *nobody*
/// configured goes is a separate question: see [`configured_database_path`].
///
/// # Errors
///
/// Returns an actionable error when a repository-controlled configuration
/// names an absolute, traversing, or symlink-escaping database path.
pub(crate) fn database_location(
    root: &Path,
    flag: Option<&Path>,
    config: &ResolvedConfig,
    untrusted: bool,
) -> Result<DatabaseLocation> {
    if let Some(path) = flag {
        return Ok(DatabaseLocation {
            configured: spelled_natively(path),
            named: true,
            confinement: None,
        });
    }
    let confine = |written: FromScannedTree<&Path>, authority: &'static str| {
        let confinement = Confinement {
            boundary: OperatorSupplied::from_command_line(root.to_path_buf()),
            written: written.as_written().to_path_buf(),
            authority,
        };
        let configured = spelled_natively(&confined_database_path(
            &confinement.boundary,
            &written,
            authority,
        )?);
        Ok::<_, anyhow::Error>(DatabaseLocation {
            configured,
            named: false,
            confinement: Some(confinement),
        })
    };
    match (configured_paths(config).database, untrusted) {
        (Authority::Operator(configured), false) => Ok(DatabaseLocation {
            configured: spelled_natively(&configured_database_path(
                &repository_root(root),
                &configured,
            )),
            named: false,
            confinement: None,
        }),
        (configured, true) => confine(configured.distrusted(), "--untrusted"),
        (Authority::Tree(configured), false) => confine(
            configured,
            "a configuration discovered in the scanned repository",
        ),
    }
}

/// Where the configured audit database is, and what may stand in for it.
///
/// Every intent — and `doctor`'s account of each — is answered by
/// [`Self::select`] on one value, so the fallback rules and the confinement
/// they owe a tree-supplied path live in one place.
pub(crate) struct DatabaseLocation {
    /// The configured database, or the one named with `--db`.
    configured: PathBuf,
    /// Whether `--db` named it; a named file is never traded for another.
    named: bool,
    /// The boundary a tree-supplied or `--untrusted` path is held to.
    confinement: Option<Confinement>,
}

/// The boundary one configured database path is held to.
struct Confinement {
    boundary: OperatorSupplied<PathBuf>,
    written: PathBuf,
    authority: &'static str,
}

/// The file one command uses, with the sentence owed when it is not the
/// configured one.
pub(crate) struct DatabaseSelection {
    /// The file to open.
    pub(crate) path: PathBuf,
    note: Option<String>,
}

impl DatabaseSelection {
    /// Print the note owed for stepping aside, if any, and hand back the path.
    pub(crate) fn announced(self) -> PathBuf {
        if let Some(note) = &self.note {
            eprintln!("{note}");
        }
        self.path
    }
}

impl DatabaseLocation {
    /// The configured database, before any fallback.
    pub(crate) fn configured(&self) -> &Path {
        &self.configured
    }

    /// The file a command with `intent` uses, without printing anything.
    ///
    /// A schema this build does not support is the one recording failure the
    /// tool can settle on its own: nothing about the existing file has to
    /// change for a scan to keep a durable record, so the run writes beside it
    /// instead of finishing with nothing recorded. Every other recording
    /// failure — a full disk, a read-only file, a lease another scan holds —
    /// still fails, because choosing a different file would not fix any of
    /// them. A neighbour is held to the configured path's boundary before it
    /// is opened.
    ///
    /// # Errors
    ///
    /// Returns an error when a confined neighbour escapes the selected tree or
    /// has a sidecar planted as a link.
    pub(crate) fn select(&self, intent: DatabaseUse) -> Result<DatabaseSelection> {
        let path = &self.configured;
        let unchanged = || DatabaseSelection {
            path: path.clone(),
            note: None,
        };
        if self.named || intent == DatabaseUse::Literal {
            return Ok(unchanged());
        }
        let incompatible = holds_another_schema(path);
        // Once the unreadable default is gone, the history this build kept
        // beside it is still the one every command has been using; starting
        // over at the default would leave it behind without a word.
        let absent = !std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0);
        if !incompatible && !absent {
            return Ok(unchanged());
        }
        let Some(sibling) = self.sibling()? else {
            return Ok(unchanged());
        };
        let note = if incompatible {
            if intent == DatabaseUse::Reading && !readable_here(&sibling) {
                return Ok(unchanged());
            }
            stepping_aside_note(path, &sibling)
        } else if readable_here(&sibling) {
            format!(
                "note: {} holds no audit database; codehelion used {}, where this build has been recording",
                path.display(),
                sibling.display()
            )
        } else {
            return Ok(unchanged());
        };
        Ok(DatabaseSelection {
            path: sibling,
            note: Some(note),
        })
    }

    /// The configured path's schema-versioned neighbour, held to the same
    /// boundary as the configured path itself.
    fn sibling(&self) -> Result<Option<PathBuf>> {
        let Some(confinement) = &self.confinement else {
            return Ok(schema_versioned_sibling(&self.configured));
        };
        let Some(written) = schema_versioned_sibling(&confinement.written) else {
            return Ok(None);
        };
        confined_database_path(
            &confinement.boundary,
            &FromScannedTree::found(written.as_path()),
            confinement.authority,
        )
        .map(|path| Some(spelled_natively(&path)))
    }
}

/// Say which database was used and which was left alone.
///
/// Announced rather than done quietly: a second audit database is as large as
/// the first one, and the reader is the only one who can decide what becomes
/// of the file this command did not touch. One wording for every command, so
/// that meeting the same situation twice does not read as two situations.
fn stepping_aside_note(left: &Path, used: &Path) -> String {
    format!(
        "note: {} was written by another schema version and was left unchanged; codehelion used {}",
        left.display(),
        used.display()
    )
}

/// Whether `path` holds a database written by a schema version this build
/// does not support.
fn holds_another_schema(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
        && matches!(
            codehelion_store::Store::open_existing(path),
            Err(codehelion_store::StoreError::UnsupportedSchema { .. })
        )
}

/// Whether `path` holds a database this build can open.
pub(crate) fn readable_here(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.len() > 0)
        && codehelion_store::Store::open_existing(path).is_ok()
}

/// Where a run goes instead of `path`, when `path` holds a database written by
/// a schema version this build does not support.
///
/// `None` for every other state, including a database this build can open and
/// one that cannot be read at all: those belong to the run's own open, which
/// reports them where they happen.
pub(crate) fn incompatible_database_replacement(path: &Path) -> Option<PathBuf> {
    if holds_another_schema(path) {
        schema_versioned_sibling(path)
    } else {
        None
    }
}

/// The next command to type, when `path` holds a database written by a schema
/// version this build does not support.
///
/// A refusal that names no way forward leaves the reader to work out that the
/// tool has a naming rule for this, which they cannot know. Naming the file is
/// enough: the two ways out are to record beside the old history or to stop
/// naming it, and both are one flag away.
///
/// `None` when `path` is fine, unreadable for some other reason, or has no
/// name a neighbour could be derived from — nothing to advise in any of those.
pub(crate) fn incompatible_database_advice(path: &Path) -> Option<String> {
    let sibling = incompatible_database_replacement(path)?;
    let already_there = readable_here(&sibling);
    let sibling = sibling.display();
    Some(if already_there {
        format!(
            "an audit history this build can open is already at {sibling}: read it with --db {sibling}, or drop --db to let codehelion choose it"
        )
    } else {
        format!(
            "record beside it with --db {sibling}, or drop --db to let codehelion choose a database it can open"
        )
    })
}

/// `path` renamed to carry the schema version this build writes.
///
/// Derived from the name actually in use rather than a fixed string, so a
/// configured database keeps its own name and the two files in one directory
/// read as what they are: the same audit history under two schema versions.
pub(crate) fn schema_versioned_sibling(path: &Path) -> Option<PathBuf> {
    let mut name = path.file_stem()?.to_os_string();
    name.push(format!("-v{}", codehelion_store::schema::SCHEMA_VERSION));
    if let Some(extension) = path.extension() {
        name.push(".");
        name.push(extension);
    }
    Some(path.with_file_name(name))
}

/// `path` with every component separated the way the platform separates them.
///
/// Where the database is gets recorded in a report and printed by every reader
/// of it, and the part of it a configuration supplies is written by hand — on
/// Windows commonly with the separator the rest of the world uses. Joining that
/// onto a resolved root leaves one path spelled two ways in the middle, which
/// reads as a typo and compares as a different file.
fn spelled_natively(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Place a database the tree had no part in choosing.
///
/// A relative location is read against the repository holding the scan root,
/// so that scanning a subtree twice from different directories keeps one audit
/// history for the project rather than scattering one per subtree. That is a
/// placement decision, not a confinement one: `configured` is something the
/// operator named or this build supplies, so there is nothing here to hold to
/// a boundary — which is why `placement` cannot be passed to
/// [`confined_database_path`] and this cannot be passed a tree-supplied path.
fn configured_database_path(
    placement: &FromScannedTree<PathBuf>,
    configured: &OperatorSupplied<&Path>,
) -> PathBuf {
    let configured = *configured.get();
    if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        placement.as_default_placement().join(configured)
    }
}

/// Keep a tree-supplied database path inside the tree the operator selected.
///
/// `boundary` is an [`OperatorSupplied`] path on purpose: a directory found by
/// inspecting the tree can sit anywhere above the one that was selected, so
/// handing one to this function has to fail to compile rather than quietly
/// widen what a configuration may reach.
fn confined_database_path(
    boundary: &OperatorSupplied<PathBuf>,
    configured: &FromScannedTree<&Path>,
    authority: &str,
) -> Result<PathBuf> {
    let boundary = boundary.get().as_path();
    let configured = configured.as_written();
    if configured.is_absolute() {
        bail!(
            "refusing database path {} from {authority}: repository configuration cannot choose storage outside {}; use --db <path> to explicitly choose an external database",
            configured.display(),
            boundary.display()
        );
    }
    if configured
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!(
            "refusing database path {} from {authority}: `..` can escape {}; use a relative path below that directory or --db <path> for an explicitly external database",
            configured.display(),
            boundary.display()
        );
    }
    let candidate = boundary.join(configured);
    ensure_existing_path_is_confined(boundary, configured, authority)?;
    ensure_sidecars_are_not_links(&candidate, authority)?;
    Ok(candidate)
}

/// The files opened beside a database under names derived from its own: the
/// scan lease and `SQLite`'s journal files.
const DATABASE_SIDECAR_SUFFIXES: [&str; 4] = [".lock", "-wal", "-shm", "-journal"];

/// Refuse a confined database whose sidecar the tree has planted as a link.
///
/// The sidecars are opened by name, following links, so a link among them
/// would have the scan create or lock a file wherever the tree pointed it.
fn ensure_sidecars_are_not_links(database: &Path, authority: &str) -> Result<()> {
    for suffix in DATABASE_SIDECAR_SUFFIXES {
        let mut name = database.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(metadata) if metadata.file_type().is_symlink() => bail!(
                "refusing database path {} from {authority}: {} is a link, which would open a file outside the database's directory; remove it or use --db <path> to explicitly choose a database",
                database.display(),
                sidecar.display()
            ),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("checking database file {}", sidecar.display()));
            }
        }
    }
    Ok(())
}

/// Reject an existing symlink component that would make a lexically confined
/// relative path leave `boundary` anyway.
fn ensure_existing_path_is_confined(
    boundary: &Path,
    configured: &Path,
    authority: &str,
) -> Result<()> {
    let mut prefix = boundary.to_path_buf();
    for component in configured.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(part) => prefix.push(part),
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                bail!(
                    "refusing database path {} from {authority}: it must be relative to {}",
                    configured.display(),
                    boundary.display()
                );
            }
        }
        match std::fs::symlink_metadata(&prefix) {
            Ok(_) => {
                let resolved = codehelion_core::paths::canonical(&prefix).with_context(|| {
                    format!("resolving database path component {}", prefix.display())
                })?;
                if !resolved.starts_with(boundary) {
                    bail!(
                        "refusing database path {} from {authority}: {} resolves outside {}; use --db <path> to explicitly choose an external database",
                        configured.display(),
                        prefix.display(),
                        boundary.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("checking database path component {}", prefix.display())
                });
            }
        }
    }
    Ok(())
}

/// Find the repository containing a scan root, falling back to the scan root
/// when it is not inside a Git worktree.
///
/// This is where a database *nobody configured* is placed, so that one project
/// keeps one audit history however many of its subtrees get scanned. It is not
/// a confinement boundary and the return type says so: the directory is found
/// by inspecting the tree, it can sit above what the operator selected, and a
/// path a configuration chose is held to `--path` instead (see
/// [`database_path_for`]). Falling back to `root` itself when no `.git` ancestor
/// exists keeps the placement inside the scan either way, rather than widening
/// to a filesystem root or refusing to scan a tree that simply isn't a Git
/// worktree.
///
/// Delegates the walk to [`crate::find_git_root`] rather than repeating it, so
/// this placement and the `.gitignore` hints in `doctor` and `scan` (the only
/// other callers of that walk) can never disagree about which ancestor holds
/// `.git`.
fn repository_root(root: &Path) -> FromScannedTree<PathBuf> {
    FromScannedTree::found(crate::find_git_root(root).unwrap_or_else(|| root.to_path_buf()))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        DatabaseUse, database_path_for, incompatible_database_replacement, repository_root,
        schema_versioned_sibling, spelled_natively,
    };
    use crate::config::{Config, ConfigSource, ResolvedConfig};

    /// Where the database is has to read as one path, whatever mixture of
    /// separators and redundant components the configuration reached it by.
    #[test]
    fn a_configured_location_is_spelled_one_way() {
        let boundary = Path::new("project");
        for configured in ["state/audit.db", "state/./audit.db", "./state/audit.db"] {
            assert_eq!(
                spelled_natively(&boundary.join(configured)),
                ["project", "state", "audit.db"].iter().collect::<PathBuf>(),
                "{configured}"
            );
        }
    }

    /// The database written beside an unreadable one keeps the name in use,
    /// so a configured location and its neighbour read as one pair rather than
    /// as two unrelated files.
    #[test]
    fn the_database_written_beside_another_keeps_the_configured_name() {
        let version = codehelion_store::schema::SCHEMA_VERSION;
        for (configured, expected) in [
            (
                ".codehelion/audit.db",
                format!(".codehelion/audit-v{version}.db"),
            ),
            (
                "state/history.sqlite",
                format!("state/history-v{version}.sqlite"),
            ),
            ("state/history", format!("state/history-v{version}")),
        ] {
            assert_eq!(
                schema_versioned_sibling(Path::new(configured)),
                Some(PathBuf::from(&expected)),
                "{configured}"
            );
        }
    }

    /// A path with no database at it needs no neighbour: a run creates it and
    /// records there, which is what an absent database is for.
    #[test]
    fn an_absent_database_is_left_for_the_run_to_create() {
        let directory = tempfile::tempdir().expect("temp dir");
        assert_eq!(
            incompatible_database_replacement(&directory.path().join("audit.db")),
            None
        );
    }

    /// Folding the spelling is not folding the path: what climbs out of a
    /// directory still climbs out of it, so the checks that refuse such a path
    /// are looking at what it says.
    #[test]
    fn respelling_a_path_does_not_resolve_it() {
        assert_eq!(
            spelled_natively(Path::new("project/../elsewhere/audit.db")),
            ["project", "..", "elsewhere", "audit.db"]
                .iter()
                .collect::<PathBuf>()
        );
    }

    /// The default database placement (`repository_root`) and the `.gitignore`
    /// hint walk (`crate::find_git_root`) delegate to the same `.git` search,
    /// so they cannot silently disagree: inside a Git worktree they name the
    /// same directory, and outside one, `repository_root`'s documented
    /// fallback to the scan root is exactly the case `find_git_root` reports
    /// as `None`.
    #[test]
    fn repository_root_and_find_git_root_agree_including_the_no_git_fallback() {
        let repository = tempfile::tempdir().expect("create repository directory");
        std::fs::create_dir(repository.path().join(".git")).expect("create .git marker");
        let nested = repository.path().join("crates/inner");
        std::fs::create_dir_all(&nested).expect("create nested working directory");

        assert_eq!(
            repository_root(&nested).as_default_placement(),
            crate::find_git_root(&nested).expect("a .git ancestor exists")
        );

        let outside = tempfile::tempdir().expect("create directory outside any repository");
        assert_eq!(crate::find_git_root(outside.path()), None);
        assert_eq!(
            repository_root(outside.path()).as_default_placement(),
            outside.path()
        );
    }

    /// A configuration the tree supplies may not choose storage outside the
    /// directory the operator pointed at, and `--untrusted` says the same
    /// about a configuration the operator named. The boundary is `--path`
    /// rather than the repository holding it: auditing a vendored subtree of
    /// one's own worktree is what the flag exists for, and there the
    /// repository root is above what was selected.
    #[test]
    fn a_configured_database_is_confined_to_the_selected_tree_not_its_repository() {
        let worktree = tempfile::tempdir().expect("create worktree directory");
        std::fs::create_dir(worktree.path().join(".git")).expect("create .git marker");
        let vendored = worktree.path().join("vendor/hostile");
        std::fs::create_dir_all(&vendored).expect("create vendored subtree");

        let config = Config {
            database: PathBuf::from("escaped/audit.db"),
            ..Config::default()
        };
        let discovered = ResolvedConfig {
            config: config.clone(),
            source: ConfigSource::Discovered(vendored.join("codehelion.toml")),
        };
        let named = ResolvedConfig {
            config,
            source: ConfigSource::Explicit(vendored.join("codehelion.toml")),
        };

        for (resolved, untrusted) in [(&discovered, false), (&discovered, true), (&named, true)] {
            let resolved_path =
                database_path_for(DatabaseUse::Literal, &vendored, None, resolved, untrusted)
                    .expect("a relative path below the selected tree is accepted");
            assert!(
                resolved_path.starts_with(&vendored),
                "{} escaped {}",
                resolved_path.display(),
                vendored.display()
            );
        }

        // The same setting from a configuration the operator named is theirs
        // to make, so without `--untrusted` it keeps the established placement
        // against the repository holding the scan.
        let trusted = database_path_for(DatabaseUse::Literal, &vendored, None, &named, false)
            .expect("an operator-named configuration places freely");
        assert_eq!(trusted, worktree.path().join("escaped/audit.db"));
    }

    /// Every refusal a tree-supplied path can earn names the selected tree,
    /// so the reader is told the boundary that actually applied rather than
    /// one it happens to sit inside.
    #[test]
    fn a_tree_supplied_database_path_that_leaves_the_selected_tree_is_refused() {
        let worktree = tempfile::tempdir().expect("create worktree directory");
        std::fs::create_dir(worktree.path().join(".git")).expect("create .git marker");
        let vendored = worktree.path().join("vendor/hostile");
        std::fs::create_dir_all(&vendored).expect("create vendored subtree");

        for spelling in ["../escaped/audit.db", "../../escaped/audit.db"] {
            let config = Config {
                database: PathBuf::from(spelling),
                ..Config::default()
            };
            let resolved = ResolvedConfig {
                config,
                source: ConfigSource::Discovered(vendored.join("codehelion.toml")),
            };
            let error = database_path_for(DatabaseUse::Literal, &vendored, None, &resolved, false)
                .expect_err("a path climbing out of the selected tree is refused");
            let message = format!("{error:#}");
            assert!(message.contains("refusing database path"), "{message}");
            assert!(
                message.contains(&vendored.display().to_string()),
                "the refusal names the selected tree: {message}"
            );
        }
    }

    /// A configuration found at a subdirectory root that never mentions the
    /// database leaves it where it is with no configuration at all: under the
    /// repository, so every subtree scan shares one history.
    #[test]
    fn a_subdirectory_configuration_without_a_database_keeps_the_repository_default() {
        let worktree = tempfile::tempdir().expect("create worktree directory");
        std::fs::create_dir(worktree.path().join(".git")).expect("create .git marker");
        let subdirectory = worktree.path().join("crates/inner");
        std::fs::create_dir_all(&subdirectory).expect("create subdirectory");

        let discovered = ResolvedConfig {
            config: Config::from_toml("min-clone-tokens = 30\n").expect("parse configuration"),
            source: ConfigSource::Discovered(subdirectory.join("codehelion.toml")),
        };
        let defaults = ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Defaults,
        };
        let expected = worktree.path().join(".codehelion/audit.db");
        for resolved in [&discovered, &defaults] {
            assert_eq!(
                database_path_for(DatabaseUse::Recording, &subdirectory, None, resolved, false)
                    .expect("the default database resolves"),
                expected
            );
        }
    }

    /// Write a database this build cannot open at `path`.
    fn database_from_another_schema(path: &Path) {
        std::fs::create_dir_all(path.parent().expect("database directory"))
            .expect("create database directory");
        codehelion_store::Store::open(path).expect("create database");
        rusqlite::Connection::open(path)
            .expect("open database")
            .execute(
                "UPDATE schema_meta SET version = ?1",
                [codehelion_store::schema::SCHEMA_VERSION + 1],
            )
            .expect("record another schema version");
    }

    /// Under `--untrusted` or a tree-supplied setting, the neighbour that
    /// stands in for the configured database is held to the same boundary:
    /// a planted link at it, or at its lease, is refused on the step-aside
    /// branch and on the branch that follows a removed default, for every
    /// intent that may leave the configured file.
    #[cfg(unix)]
    #[test]
    fn a_neighbour_planted_as_a_link_out_of_the_tree_is_refused_on_every_branch() {
        let outside = tempfile::tempdir().expect("create outside directory");
        let target = outside.path().join("elsewhere.db");
        codehelion_store::Store::open(&target).expect("create the outside database");
        let sibling_name = format!("audit-v{}.db", codehelion_store::schema::SCHEMA_VERSION);

        for planted in [sibling_name.clone(), format!("{sibling_name}.lock")] {
            for default_present in [true, false] {
                let tree = tempfile::tempdir().expect("create tree");
                let root =
                    codehelion_core::paths::canonical(tree.path()).expect("canonical tree root");
                let state = root.join(".codehelion");
                std::fs::create_dir_all(&state).expect("create state directory");
                if default_present {
                    database_from_another_schema(&state.join("audit.db"));
                }
                std::os::unix::fs::symlink(&target, state.join(&planted))
                    .expect("plant a link out of the tree");

                let defaults = ResolvedConfig {
                    config: Config::default(),
                    source: ConfigSource::Defaults,
                };
                for intent in [DatabaseUse::Recording, DatabaseUse::Reading] {
                    let error = database_path_for(intent, &root, None, &defaults, true)
                        .expect_err("a neighbour linked out of the tree is refused");
                    let message = format!("{error:#}");
                    assert!(
                        message.contains("refusing database path"),
                        "{planted} default_present={default_present} {intent:?}: {message}"
                    );
                }
                // The configured file itself passes the same checks and is
                // still described as configured.
                assert_eq!(
                    database_path_for(DatabaseUse::Literal, &root, None, &defaults, true)
                        .expect("the configured path is inside the tree"),
                    state.join("audit.db")
                );
            }
        }
    }

    /// The configured file is refused by the same checks its neighbour gets.
    #[cfg(unix)]
    #[test]
    fn a_configured_database_lease_planted_as_a_link_is_refused_for_every_intent() {
        let outside = tempfile::tempdir().expect("create outside directory");
        let tree = tempfile::tempdir().expect("create tree");
        let root = codehelion_core::paths::canonical(tree.path()).expect("canonical tree root");
        let state = root.join(".codehelion");
        std::fs::create_dir_all(&state).expect("create state directory");
        std::os::unix::fs::symlink(outside.path().join("lease"), state.join("audit.db.lock"))
            .expect("plant a link out of the tree");
        let defaults = ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Defaults,
        };
        for intent in [
            DatabaseUse::Recording,
            DatabaseUse::Reading,
            DatabaseUse::Literal,
        ] {
            let error = database_path_for(intent, &root, None, &defaults, true)
                .expect_err("a lease linked out of the tree is refused");
            assert!(
                format!("{error:#}").contains("refusing database path"),
                "{intent:?}: {error:#}"
            );
        }
    }

    /// A tree-supplied database setting gets the same check on its neighbour
    /// without `--untrusted`.
    #[cfg(unix)]
    #[test]
    fn a_tree_supplied_database_neighbour_planted_as_a_link_is_refused() {
        let outside = tempfile::tempdir().expect("create outside directory");
        let tree = tempfile::tempdir().expect("create tree");
        let root = codehelion_core::paths::canonical(tree.path()).expect("canonical tree root");
        let state = root.join("state");
        database_from_another_schema(&state.join("history.db"));
        std::os::unix::fs::symlink(
            outside.path().join("planted.db"),
            state.join(format!(
                "history-v{}.db",
                codehelion_store::schema::SCHEMA_VERSION
            )),
        )
        .expect("plant a link out of the tree");
        let discovered = ResolvedConfig {
            config: Config {
                database: PathBuf::from("state/history.db"),
                ..Config::default()
            },
            source: ConfigSource::Discovered(root.join("codehelion.toml")),
        };
        // A dangling link cannot be resolved, which refuses it as well.
        database_path_for(DatabaseUse::Recording, &root, None, &discovered, false)
            .expect_err("the neighbour is confined like the configured path");
        assert!(
            !outside.path().join("planted.db").exists(),
            "nothing was created outside the tree"
        );
    }

    /// A neighbour inside the tree is still used on every branch under
    /// confinement.
    #[test]
    fn a_confined_neighbour_inside_the_tree_is_used() {
        let tree = tempfile::tempdir().expect("create tree");
        let root = codehelion_core::paths::canonical(tree.path()).expect("canonical tree root");
        let state = root.join(".codehelion");
        database_from_another_schema(&state.join("audit.db"));
        let defaults = ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Defaults,
        };
        let sibling = state.join(format!(
            "audit-v{}.db",
            codehelion_store::schema::SCHEMA_VERSION
        ));
        assert_eq!(
            database_path_for(DatabaseUse::Recording, &root, None, &defaults, true)
                .expect("the neighbour is inside the tree"),
            sibling
        );
    }
}
