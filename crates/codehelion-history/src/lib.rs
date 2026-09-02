//! Reads a local git history into the commit records a seam analysis is
//! computed from.
//!
//! This crate knows nothing about source code. It answers four questions about
//! a repository — which commits are in range, when each was committed, what
//! kind of change its subject declares, and which paths it touched — and
//! nothing else depends on it to answer more. Clone detection, the audit
//! store and the analysis engine are all absent from its dependency list, so
//! the time axis can be tested on its own.
//!
//! # Why the reading is pinned rather than convenient
//!
//! Every number a seam report prints is a count over these records, so a record
//! set that shifts between two runs makes the report unusable for comparing one
//! generation against the next. Four decisions keep it from shifting:
//!
//! - **Commits are ordered by `(committer time, commit id)`, ascending.** Git's
//!   own traversal order is a property of the object graph and of the options
//!   it was asked for; this order is a property of the commits themselves.
//! - **Merges are followed by first parent only.** What a topic branch did
//!   internally is not this layer's subject; what landed on the trunk is.
//! - **Rename detection is off.** Git's rename detection is a similarity
//!   heuristic, and its answer moves with its threshold. A rename is read as a
//!   deletion and an addition, which cuts a path's history at the move — a cost
//!   accepted deliberately, and documented, rather than traded for a number
//!   that depends on which git computed it.
//! - **A commit's kind comes from its Conventional Commits prefix alone.**
//!   Searching the message for words like "fix" or "bug" would classify prose,
//!   and prose is exactly what differs between two authors describing the same
//!   change.
//!
//! Nothing here reaches the network: the crate opens `.git` and reads it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A commit's object id, as forty lowercase hexadecimal characters.
///
/// Held as text because that is how it is written to a report and compared
/// against one recorded earlier. Ordering the text orders the bytes, so it can
/// serve as the tie-break in the traversal order without a separate encoding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommitId(String);

impl CommitId {
    /// The id as it is written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The leading characters a report names a commit by.
    ///
    /// Short enough to read in a table and long enough to stay unique across a
    /// history far larger than the ceiling this crate reads.
    #[must_use]
    pub fn abbreviated(&self) -> &str {
        let end = self.0.len().min(ABBREVIATED_ID_LENGTH);
        &self.0[..end]
    }
}

/// How many leading characters of a commit id a report prints.
const ABBREVIATED_ID_LENGTH: usize = 8;

impl std::fmt::Display for CommitId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A path as the repository spells it: relative to the repository root, with
/// forward slashes on every platform.
///
/// Normalised at the boundary rather than at each use, so a glob written in a
/// seam ledger means the same thing wherever the tool runs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepoPath(String);

impl RepoPath {
    /// Record a path already spelled the repository's way.
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self(path.into())
    }

    /// Read a path the host filesystem spelled, converting separators.
    #[must_use]
    pub fn from_host_path(path: &Path) -> Self {
        let mut spelled = String::new();
        for component in path.components() {
            if let std::path::Component::Normal(part) = component {
                if !spelled.is_empty() {
                    spelled.push('/');
                }
                spelled.push_str(&part.to_string_lossy());
            }
        }
        Self(spelled)
    }

    /// The path as it is written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first `depth` path components, or the whole path when it has fewer.
    ///
    /// What co-change is counted over when a seam has not been written down
    /// yet. A file is too fine a unit to see a pair of parallel implementations
    /// in, and the whole tree is too coarse to see anything at all.
    #[must_use]
    pub fn leading_components(&self, depth: usize) -> Self {
        if depth == 0 {
            return Self(String::new());
        }
        let mut end = self.0.len();
        let mut seen = 0;
        for (index, character) in self.0.char_indices() {
            if character == '/' {
                seen += 1;
                if seen == depth {
                    end = index;
                    break;
                }
            }
        }
        Self(self.0[..end].to_string())
    }
}

impl std::fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// What kind of change a commit's subject declares.
///
/// Read from the Conventional Commits prefix and from nothing else. A
/// repository that does not write those prefixes reports every commit as
/// [`Other`](CommitKind::Other), which costs breach detection and costs nothing
/// else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitKind {
    /// The subject is prefixed `fix`, with or without a scope or a `!`.
    Fix,
    /// The subject is prefixed `feat`.
    Feat,
    /// Any other prefix, or no prefix at all.
    Other,
}

impl CommitKind {
    /// The kind a subject line declares.
    ///
    /// A prefix is a lowercase word, an optional parenthesised scope, an
    /// optional `!`, then a colon — matched exactly, with no fallback to
    /// searching the text. `Fixed a crash` is [`Other`](CommitKind::Other), and
    /// deliberately so: what makes the prefix usable as evidence is that a hook
    /// can require it, and no hook can require prose to mean what a reader
    /// takes it to mean.
    #[must_use]
    pub fn from_subject(subject: &str) -> Self {
        let Some(prefix) = subject.split(':').next() else {
            return Self::Other;
        };
        if prefix.len() == subject.len() {
            // No colon: nothing declared a kind.
            return Self::Other;
        }
        let prefix = prefix.strip_suffix('!').unwrap_or(prefix);
        let word = match prefix.find('(') {
            Some(open) => {
                if !prefix.ends_with(')') {
                    return Self::Other;
                }
                &prefix[..open]
            }
            None => prefix,
        };
        if word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return Self::Other;
        }
        match word {
            "fix" => Self::Fix,
            "feat" => Self::Feat,
            _ => Self::Other,
        }
    }

    /// The name this kind is reported under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fix => "fix",
            Self::Feat => "feat",
            Self::Other => "other",
        }
    }
}

/// One commit, reduced to what a seam analysis reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRecord {
    /// The commit's object id.
    pub id: CommitId,
    /// Committer timestamp in seconds since the epoch, the primary sort key.
    ///
    /// The committer time rather than the author time: rebasing rewrites the
    /// former and preserves the latter, and what this orders is the sequence a
    /// branch actually received, not the sequence somebody wrote in.
    pub committer_time: i64,
    /// What the subject declares this change to be.
    pub kind: CommitKind,
    /// The subject line, for naming the commit in a report.
    pub subject: String,
    /// Every path the commit changed, sorted and deduplicated.
    pub paths: Vec<RepoPath>,
}

impl CommitRecord {
    /// Whether this commit is large enough to be left out of coupling.
    ///
    /// A commit touching most of the tree hands support to every pair of paths
    /// in it, which is co-change in arithmetic and nothing in fact. The ceiling
    /// applies to coupling alone: leaving such a commit out of breach detection
    /// would erase the record of an asymmetric change that did happen.
    #[must_use]
    pub const fn is_sweeping(&self, max_commit_size: usize) -> bool {
        self.paths.len() > max_commit_size
    }
}

/// Which commits a set of records was read over.
///
/// Carried alongside every result so that two runs' numbers can be compared
/// honestly: a count that moved because the range moved is not a count that
/// moved because the code did.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HistoryRange {
    /// Oldest commit read, or `None` for an empty range.
    pub first: Option<CommitId>,
    /// Newest commit read, or `None` for an empty range.
    pub last: Option<CommitId>,
    /// How many commits were read.
    pub commits: usize,
}

/// What to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRequest {
    /// Ceiling on how many commits are read, newest first.
    ///
    /// A resource ceiling and a determinism tool at once: without a fixed
    /// range, a repository that grew between two runs cannot be compared with
    /// itself.
    pub limit: usize,
    /// Revision to start the walk at, or `None` for `HEAD`.
    pub until: Option<String>,
}

impl Default for HistoryRequest {
    fn default() -> Self {
        Self {
            limit: DEFAULT_HISTORY_LIMIT,
            until: None,
        }
    }
}

/// Commits read when nothing says otherwise.
pub const DEFAULT_HISTORY_LIMIT: usize = 2000;

/// A read history, in the pinned order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct History {
    /// Commits, ascending by `(committer time, commit id)`.
    commits: Vec<CommitRecord>,
    /// Whether the repository is a shallow clone, whose history is cut at a
    /// depth nobody chose for this analysis.
    shallow: bool,
}

impl History {
    /// Hold an already-ordered set of records.
    ///
    /// The order is re-established here rather than trusted, so that a caller
    /// assembling records by hand — a test, or a future reader other than git —
    /// cannot introduce an order the analysis would then depend on.
    #[must_use]
    pub fn new(mut commits: Vec<CommitRecord>, shallow: bool) -> Self {
        commits.sort_by(|left, right| {
            left.committer_time
                .cmp(&right.committer_time)
                .then_with(|| left.id.cmp(&right.id))
        });
        Self { commits, shallow }
    }

    /// The commits, oldest first.
    #[must_use]
    pub fn commits(&self) -> &[CommitRecord] {
        &self.commits
    }

    /// Whether the repository's history was cut by a shallow clone.
    ///
    /// Reported rather than refused: a shallow checkout still answers "what did
    /// this commit touch", which is all `guard` needs. What it cannot answer is
    /// how often two paths moved together, and a count computed over one commit
    /// would look like an answer.
    #[must_use]
    pub const fn is_shallow(&self) -> bool {
        self.shallow
    }

    /// Which commits this history covers.
    #[must_use]
    pub fn range(&self) -> HistoryRange {
        HistoryRange {
            first: self.commits.first().map(|commit| commit.id.clone()),
            last: self.commits.last().map(|commit| commit.id.clone()),
            commits: self.commits.len(),
        }
    }
}

/// Something that went wrong reading a repository.
#[derive(Debug, thiserror::Error)]
pub enum HistoryError {
    /// The path is not inside a git repository.
    #[error("no git repository at {}", .path.display())]
    NotARepository {
        /// The directory that was opened.
        path: PathBuf,
        /// What git said about it.
        message: String,
    },
    /// The repository has no commits yet.
    #[error("repository at {} has no commits", .0.display())]
    Unborn(PathBuf),
    /// A revision could not be resolved.
    #[error("cannot resolve revision {revision:?}: {message}")]
    UnknownRevision {
        /// The revision as it was written.
        revision: String,
        /// What git said about it.
        message: String,
    },
    /// The repository could be opened but could not be read.
    #[error("reading git history: {0}")]
    Read(String),
    /// A path in the repository is not valid UTF-8.
    ///
    /// Refused rather than lossily converted: a seam ledger matches globs
    /// against these, and a path silently replaced by one with a substitution
    /// character would be matched against the wrong glob without saying so.
    #[error("path {0:?} in the repository is not valid UTF-8")]
    NonUtf8Path(String),
}

/// Read a repository's history.
///
/// # Errors
///
/// Returns an error when `repo_root` is not a repository, when it has no
/// commits, when `request.until` names nothing, or when git could not be read.
pub fn read(repo_root: &Path, request: &HistoryRequest) -> Result<History, HistoryError> {
    let repository = open(repo_root)?;
    let shallow = repository.is_shallow();
    let start = resolve(&repository, request.until.as_deref())?;

    // Newest first along first parents, up to the ceiling. The ceiling is
    // applied to the walk rather than to the result so that a large repository
    // costs the same as a small one.
    let mut walked = Vec::new();
    let mut current = Some(start);
    while let Some(id) = current {
        if walked.len() >= request.limit {
            break;
        }
        let commit = repository
            .find_commit(id)
            .map_err(|error| HistoryError::Read(error.to_string()))?;
        let parent = commit.parent_ids().next().map(gix::Id::detach);
        walked.push(record(&repository, &commit)?);
        current = parent;
    }

    Ok(History::new(walked, shallow))
}

/// Every path that differs between the working tree and `HEAD`.
///
/// Both halves of the comparison are included — what is staged and what is not
/// — along with files git is not yet tracking, because adding a file to one
/// member of a seam and not to the other is exactly the change worth reporting.
/// Ignored files stay out.
///
/// # Errors
///
/// Returns an error when the repository cannot be opened or its status cannot
/// be computed.
pub fn working_tree_changes(repo_root: &Path) -> Result<Vec<RepoPath>, HistoryError> {
    let repository = open(repo_root)?;
    let iterator = repository
        .status(gix::progress::Discard)
        .map_err(|error| HistoryError::Read(error.to_string()))?
        // Individual files rather than collapsed directories: a glob in a seam
        // ledger is written against files.
        .untracked_files(gix::status::UntrackedFiles::Files)
        // Rename tracking off on both halves, for the reason the tree walk has
        // it off.
        .index_worktree_rewrites(None)
        .tree_index_track_renames(gix::status::tree_index::TrackRenames::Disabled)
        .into_iter(None)
        .map_err(|error| HistoryError::Read(error.to_string()))?;

    let mut paths = BTreeSet::new();
    for item in iterator {
        let item = item.map_err(|error| HistoryError::Read(error.to_string()))?;
        paths.insert(repo_path(item.location().as_ref())?);
    }
    Ok(paths.into_iter().collect())
}

/// Every path that differs between `revision` and `HEAD`.
///
/// # Errors
///
/// Returns an error when the repository cannot be opened, when either revision
/// names nothing, or when the trees cannot be compared.
pub fn changes_since(repo_root: &Path, revision: &str) -> Result<Vec<RepoPath>, HistoryError> {
    let repository = open(repo_root)?;
    let before = resolve(&repository, Some(revision))?;
    let after = resolve(&repository, None)?;
    let before = tree_of(&repository, before)?;
    let after = tree_of(&repository, after)?;
    let mut paths = BTreeSet::new();
    collect_changed_paths(&repository, Some(&before), &after, &mut paths)?;
    Ok(paths.into_iter().collect())
}

/// Open a repository without letting it discover one further up.
///
/// A scan is rooted where the operator pointed it. Walking up to whatever
/// checkout happens to enclose that directory would make the answer depend on
/// where the tree was unpacked, which is the same reason the configuration file
/// is looked for at the root and nowhere above it.
fn open(repo_root: &Path) -> Result<gix::Repository, HistoryError> {
    gix::open(repo_root).map_err(|error| HistoryError::NotARepository {
        path: repo_root.to_path_buf(),
        message: error.to_string(),
    })
}

/// Resolve a revision, or `HEAD` when none was named.
fn resolve(
    repository: &gix::Repository,
    revision: Option<&str>,
) -> Result<gix::ObjectId, HistoryError> {
    revision.map_or_else(
        || {
            repository
                .head_commit()
                .map(|commit| commit.id)
                .map_err(|_| HistoryError::Unborn(repository.path().to_path_buf()))
        },
        |spec| {
            repository
                .rev_parse_single(spec)
                .map(gix::Id::detach)
                .map_err(|error| HistoryError::UnknownRevision {
                    revision: spec.to_string(),
                    message: error.to_string(),
                })
        },
    )
}

/// The tree a commit-ish points at.
fn tree_of(repository: &gix::Repository, id: gix::ObjectId) -> Result<gix::Tree<'_>, HistoryError> {
    let object = repository
        .find_object(id)
        .map_err(|error| HistoryError::Read(error.to_string()))?;
    object
        .peel_to_tree()
        .map_err(|error| HistoryError::Read(error.to_string()))
}

/// Reduce one commit to its record.
fn record(
    repository: &gix::Repository,
    commit: &gix::Commit<'_>,
) -> Result<CommitRecord, HistoryError> {
    let committer = commit
        .committer()
        .map_err(|error| HistoryError::Read(error.to_string()))?;
    let subject = commit
        .message()
        .map_err(|error| HistoryError::Read(error.to_string()))?
        .summary()
        .to_string();
    let new_tree = commit
        .tree()
        .map_err(|error| HistoryError::Read(error.to_string()))?;
    // A root commit is compared against nothing, which makes every path in it
    // an addition. That is the same answer git gives, and it keeps the first
    // commit from being a hole in the co-change counts.
    let old_tree = match commit.parent_ids().next() {
        Some(parent) => Some(tree_of(repository, parent.detach())?),
        None => None,
    };
    let mut paths = BTreeSet::new();
    collect_changed_paths(repository, old_tree.as_ref(), &new_tree, &mut paths)?;

    Ok(CommitRecord {
        id: CommitId(commit.id().to_string()),
        committer_time: committer.seconds(),
        kind: CommitKind::from_subject(&subject),
        subject,
        paths: paths.into_iter().collect(),
    })
}

/// Every path that differs between two trees, with rename detection off.
///
/// The options are supplied explicitly rather than left to be filled in from
/// the repository's configuration. Git's own defaults enable rename tracking,
/// and a repository could enable it in its own `.gitconfig`; either way the
/// result would depend on a similarity threshold this analysis never chose.
fn collect_changed_paths(
    repository: &gix::Repository,
    old_tree: Option<&gix::Tree<'_>>,
    new_tree: &gix::Tree<'_>,
    into: &mut BTreeSet<RepoPath>,
) -> Result<(), HistoryError> {
    let changes = repository
        .diff_tree_to_tree(old_tree, new_tree, gix::diff::Options::default())
        .map_err(|error| HistoryError::Read(error.to_string()))?;
    for change in changes {
        use gix::object::tree::diff::ChangeDetached as Change;
        let (location, entry_mode) = match &change {
            Change::Addition {
                location,
                entry_mode,
                ..
            }
            | Change::Deletion {
                location,
                entry_mode,
                ..
            }
            | Change::Modification {
                location,
                entry_mode,
                ..
            } => (location, entry_mode),
            // Unreachable while rewrites stay disabled above, and folded into
            // its two halves rather than ignored, so that turning them on later
            // cannot silently drop a path.
            Change::Rewrite {
                source_location,
                source_entry_mode,
                ..
            } => (source_location, source_entry_mode),
        };
        // A directory whose contents changed is reported alongside the files
        // inside it. Counting both would make a commit that added one file to
        // a new directory look like a commit that touched several paths, which
        // moves the commit-size ceiling and every co-change figure taken under
        // it. What a seam is written against is files.
        if entry_mode.is_tree() {
            continue;
        }
        into.insert(repo_path(location.as_ref())?);
    }
    Ok(())
}

/// Read a git path, which is bytes, as the text a glob is matched against.
fn repo_path(location: &[u8]) -> Result<RepoPath, HistoryError> {
    std::str::from_utf8(location)
        .map(RepoPath::new)
        .map_err(|_| HistoryError::NonUtf8Path(String::from_utf8_lossy(location).into_owned()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_kind_is_read_from_the_conventional_prefix_and_from_nothing_else() {
        for (subject, expected) in [
            ("fix: hold one answer", CommitKind::Fix),
            ("fix(core): hold one answer", CommitKind::Fix),
            ("fix!: hold one answer", CommitKind::Fix),
            ("fix(core)!: hold one answer", CommitKind::Fix),
            ("feat: add a thing", CommitKind::Feat),
            ("feat(cli)!: add a thing", CommitKind::Feat),
            ("docs: say what it does", CommitKind::Other),
            ("test(backend-rust): confine the tree", CommitKind::Other),
            // Prose is never classified: what makes the prefix usable is that
            // a hook can require it, and no hook can require prose.
            ("Fixed a crash in the parser", CommitKind::Other),
            ("this fixes a bug", CommitKind::Other),
            ("Fix: capitalised", CommitKind::Other),
            ("fix the thing", CommitKind::Other),
            ("", CommitKind::Other),
            (":", CommitKind::Other),
            ("fix(core: unbalanced", CommitKind::Other),
        ] {
            assert_eq!(
                CommitKind::from_subject(subject),
                expected,
                "subject {subject:?}"
            );
        }
    }

    #[test]
    fn a_history_is_ordered_by_time_then_by_id_whatever_order_it_arrives_in() {
        let commit = |id: &str, time: i64| CommitRecord {
            id: CommitId(id.to_string()),
            committer_time: time,
            kind: CommitKind::Other,
            subject: String::new(),
            paths: Vec::new(),
        };
        let history = History::new(
            vec![
                commit("bb", 20),
                commit("aa", 20),
                commit("cc", 10),
                commit("dd", 30),
            ],
            false,
        );
        let order: Vec<&str> = history
            .commits()
            .iter()
            .map(|record| record.id.as_str())
            .collect();
        // Same second, so the id decides, and it decides the same way every
        // time rather than the way the walk happened to reach them.
        assert_eq!(order, ["cc", "aa", "bb", "dd"]);
        assert_eq!(history.range().first.unwrap().as_str(), "cc");
        assert_eq!(history.range().last.unwrap().as_str(), "dd");
        assert_eq!(history.range().commits, 4);
    }

    #[test]
    fn a_units_depth_cuts_a_path_at_a_component_boundary() {
        let path = RepoPath::new("crates/codehelion-frontend-c/src/lib.rs");
        assert_eq!(path.leading_components(1).as_str(), "crates");
        assert_eq!(
            path.leading_components(2).as_str(),
            "crates/codehelion-frontend-c"
        );
        assert_eq!(
            path.leading_components(9).as_str(),
            "crates/codehelion-frontend-c/src/lib.rs"
        );
        assert_eq!(path.leading_components(0).as_str(), "");
        // A path shorter than the depth is its own unit rather than a prefix of
        // one that does not exist.
        assert_eq!(
            RepoPath::new("Makefile").leading_components(2).as_str(),
            "Makefile"
        );
    }

    #[test]
    fn a_sweeping_commit_is_the_one_above_the_ceiling_not_at_it() {
        let with_paths = |count: usize| CommitRecord {
            id: CommitId("0".repeat(40)),
            committer_time: 0,
            kind: CommitKind::Other,
            subject: String::new(),
            paths: (0..count).map(|n| RepoPath::new(n.to_string())).collect(),
        };
        assert!(!with_paths(30).is_sweeping(30));
        assert!(with_paths(31).is_sweeping(30));
    }

    #[test]
    fn a_host_path_is_read_into_the_repository_spelling() {
        let path = RepoPath::from_host_path(Path::new("crates").join("a").join("b.rs").as_path());
        assert_eq!(path.as_str(), "crates/a/b.rs");
    }

    #[test]
    fn an_abbreviated_id_is_short_enough_to_read_and_never_panics_on_a_short_one() {
        assert_eq!(CommitId("a".repeat(40)).abbreviated(), "aaaaaaaa");
        assert_eq!(CommitId("abc".to_string()).abbreviated(), "abc");
    }
}
