//! Plants a git repository whose commit ids are the same on every machine.
//!
//! A history reader is judged by the commits it returns, so testing one needs a
//! repository whose commits are known before it is read. Shipping a `.git`
//! directory as a tarball would give that, at the price of an opaque binary
//! nobody can review; what is planted here is a table instead — subjects,
//! files, deletions — and the repository is built from it when the test runs.
//!
//! # Why the commit ids come out the same everywhere
//!
//! A commit id is the hash of the tree, the parents, the two identities, the
//! two timestamps and the message. Every one of those is fixed here, because a
//! golden test on a commit id is worth nothing if the id depends on who ran it:
//!
//! - **The identity and the clock are pinned.** Author and committer are the
//!   same fixed name and address, dated from [`FIRST_COMMIT_TIME`] and stepped
//!   by [`COMMIT_INTERVAL`] per commit. The dates are written as `@<seconds>
//!   +0000` so that no local timezone reaches the object.
//! - **The host's git configuration is switched off.** `GIT_CONFIG_GLOBAL` and
//!   `GIT_CONFIG_SYSTEM` point at a file that is never created, so a developer's
//!   `commit.gpgsign`, `init.defaultBranch`, `core.autocrlf` or `diff.renames`
//!   cannot reach the result. The settings this crate actually depends on are
//!   then passed explicitly rather than left to a default.
//! - **No hook runs.** `core.hooksPath` points at a directory that is not there,
//!   and commits are made with `--no-verify`. This repository's own `commit-msg`
//!   hook has opinions about subject lines, and a fixture subject exists to be
//!   read back rather than to satisfy them.
//! - **Nothing is created that was not planned.** No `.gitignore`, no initial
//!   README, no empty commit: a file appears in a planted tree only because a
//!   [`PlannedCommit`] wrote it.
//!
//! # Why this shells out to `git`
//!
//! The product reads repositories with `gix`, and deliberately: an external
//! binary's output can move between versions, which is exactly what the history
//! layer must not depend on. That argument is about the thing being measured.
//! This is the *input* to a measurement — a repository has to be built by
//! something, and building it with the same library that reads it would let one
//! library's misunderstanding cancel out the other's. So the fixture is written
//! by `git` and read by `gix`, and the two have to agree.

// Spawning a process is what the workspace forbids on the scan path, and this
// is neither: it builds a repository for a test to read, and the only program
// it ever runs is `git` against a directory this module created.
#![allow(clippy::disallowed_types)]

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::FixtureError;

/// The name every planted commit is authored and committed by.
pub const IDENTITY_NAME: &str = "Codehelion Fixture";

/// The address every planted commit is authored and committed by.
///
/// Under `.invalid`, which is reserved never to resolve, so nothing can mistake
/// it for a person.
pub const IDENTITY_EMAIL: &str = "fixture@codehelion.invalid";

/// The second the first planted commit is dated, in seconds since the epoch.
pub const FIRST_COMMIT_TIME: i64 = 1_700_000_000;

/// Seconds between one planted commit and the next.
///
/// Wide enough that a reader ordering by committer time sees the planting order
/// unless a test asks for the clock to be held still.
pub const COMMIT_INTERVAL: i64 = 60;

/// The branch a planted repository starts on.
///
/// Named here rather than left to `init.defaultBranch`, which is a property of
/// the machine.
pub const DEFAULT_BRANCH: &str = "main";

/// One commit in a planted history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedCommit {
    /// Subject line, written verbatim.
    pub subject: &'static str,
    /// Files this commit writes, as (repository-relative path, contents).
    pub writes: &'static [(&'static str, &'static str)],
    /// Files this commit deletes.
    pub removes: &'static [&'static str],
}

impl PlannedCommit {
    /// A commit that only writes files.
    #[must_use]
    pub const fn writing(
        subject: &'static str,
        writes: &'static [(&'static str, &'static str)],
    ) -> Self {
        Self {
            subject,
            writes,
            removes: &[],
        }
    }

    /// A commit that only deletes files.
    #[must_use]
    pub const fn removing(subject: &'static str, removes: &'static [&'static str]) -> Self {
        Self {
            subject,
            writes: &[],
            removes,
        }
    }
}

/// Plant a repository holding exactly these commits, oldest first.
///
/// The repository is created at `root`, which is created if it is not there.
/// Use [`Planter`] instead when a test needs a shape a list cannot express — a
/// branch, a merge, a tag, or a working tree left dirty on purpose.
///
/// # Errors
///
/// Fails if `git` cannot be run, if any git command fails, or if a planned file
/// cannot be written.
pub fn plant(root: &Path, commits: &[PlannedCommit]) -> Result<(), FixtureError> {
    let mut planter = Planter::initialise(root)?;
    for commit in commits {
        planter.commit(commit)?;
    }
    Ok(())
}

/// The ids of a planted repository's commits, oldest first.
///
/// Read along first parents, which is planting order for a history built by
/// [`plant`] and the trunk alone for one built with a merge.
///
/// # Errors
///
/// Fails if `git` cannot be run or the repository has no commits.
pub fn commit_ids(root: &Path) -> Result<Vec<String>, FixtureError> {
    let listed = run(
        root,
        FIRST_COMMIT_TIME,
        &["rev-list", "--first-parent", "--reverse", "HEAD"],
    )?;
    Ok(listed.lines().map(str::to_string).collect())
}

/// A repository being planted, holding the clock between commits.
#[derive(Debug)]
pub struct Planter {
    /// Where the repository is.
    root: PathBuf,
    /// The second the next commit will be dated.
    time: i64,
    /// How far the clock moves after each commit; zero once it is held.
    step: i64,
    /// The commits planted so far, in the order they were planted.
    ids: Vec<String>,
}

impl Planter {
    /// Create an empty repository at `root`, on [`DEFAULT_BRANCH`].
    ///
    /// # Errors
    ///
    /// Fails if `root` cannot be created or `git init` fails.
    pub fn initialise(root: &Path) -> Result<Self, FixtureError> {
        std::fs::create_dir_all(root).map_err(|source| FixtureError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let planter = Self {
            root: root.to_path_buf(),
            time: FIRST_COMMIT_TIME,
            step: COMMIT_INTERVAL,
            ids: Vec::new(),
        };
        planter.git(&["init", "-b", DEFAULT_BRANCH])?;
        Ok(planter)
    }

    /// Where the repository is.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The commits planted so far, in planting order.
    #[must_use]
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    /// Stop the clock, so every commit planted afterwards shares one second.
    ///
    /// What a reader does with commits that carry the same timestamp is a
    /// question a fixture has to be able to ask, and a clock that always
    /// advances can never ask it.
    pub const fn hold_clock(&mut self) {
        self.step = 0;
    }

    /// Plant one commit and return its id.
    ///
    /// # Errors
    ///
    /// Fails if a planned file cannot be written, if a deleted file is not
    /// tracked, or if the commit would be empty — git reports each of those, and
    /// its message is carried out in the error.
    pub fn commit(&mut self, commit: &PlannedCommit) -> Result<String, FixtureError> {
        for (path, contents) in commit.writes {
            let target = self.root.join(path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|source| FixtureError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            std::fs::write(&target, contents).map_err(|source| FixtureError::Io {
                path: target.clone(),
                source,
            })?;
            self.git(&["add", "--all", "--", path])?;
        }
        for path in commit.removes {
            self.git(&["rm", "--quiet", "--", path])?;
        }
        // `--cleanup=verbatim` so the subject is the bytes the table wrote:
        // the default strips trailing whitespace and lines that open with `#`,
        // and a reader asserting on a subject should be reading the plan.
        self.git(&[
            "commit",
            "--no-verify",
            "--cleanup=verbatim",
            "-m",
            commit.subject,
        ])?;
        self.record_head()
    }

    /// Stage a path that was written into the working tree directly.
    ///
    /// # Errors
    ///
    /// Fails if git refuses the path.
    pub fn stage(&self, path: &str) -> Result<(), FixtureError> {
        self.git(&["add", "--all", "--", path])?;
        Ok(())
    }

    /// Start a branch at the current commit and switch to it.
    ///
    /// # Errors
    ///
    /// Fails if the branch already exists or the repository has no commits.
    pub fn branch(&self, name: &str) -> Result<(), FixtureError> {
        self.git(&["checkout", "-q", "-b", name])?;
        Ok(())
    }

    /// Switch to an existing branch.
    ///
    /// # Errors
    ///
    /// Fails if the branch does not exist.
    pub fn switch(&self, name: &str) -> Result<(), FixtureError> {
        self.git(&["checkout", "-q", name])?;
        Ok(())
    }

    /// Name the current commit, with a lightweight tag.
    ///
    /// Lightweight rather than annotated: an annotated tag is an object of its
    /// own, with its own timestamp, and nothing here needs one.
    ///
    /// # Errors
    ///
    /// Fails if the tag already exists.
    pub fn tag(&self, name: &str) -> Result<(), FixtureError> {
        self.git(&["tag", name])?;
        Ok(())
    }

    /// Merge `branch` into the current branch, keeping the merge commit.
    ///
    /// `--no-ff` always: a fast-forward would leave no merge commit, and a merge
    /// commit is the whole subject of a first-parent walk.
    ///
    /// # Errors
    ///
    /// Fails if the merge conflicts or the branch does not exist.
    pub fn merge(&mut self, branch: &str, subject: &str) -> Result<String, FixtureError> {
        self.git(&["merge", "--no-ff", "--no-edit", "-m", subject, branch])?;
        self.record_head()
    }

    /// Record the commit just made and move the clock on.
    fn record_head(&mut self) -> Result<String, FixtureError> {
        let id = self.git(&["rev-parse", "HEAD"])?;
        self.ids.push(id.clone());
        self.time += self.step;
        Ok(id)
    }

    /// Run one git command in this repository, at the current clock.
    fn git(&self, arguments: &[&str]) -> Result<String, FixtureError> {
        run(&self.root, self.time, arguments)
    }
}

/// Run one git command with everything the host could decide pinned down.
fn run(root: &Path, time: i64, arguments: &[&str]) -> Result<String, FixtureError> {
    // A path that is never created. Git reads a missing configuration file as
    // an empty one, which is what "the developer's settings do not apply" needs
    // to mean.
    let absent = root.join("codehelion-fixture-absent");
    let date = format!("@{time} +0000");
    let mut command = Command::new("git");
    command
        .current_dir(root)
        // Settings this fixture depends on, stated rather than defaulted.
        .arg("-c")
        .arg(format!("core.hooksPath={}", absent.display()))
        .arg("-c")
        .arg("commit.gpgsign=false")
        .arg("-c")
        .arg("tag.gpgsign=false")
        .arg("-c")
        .arg("core.autocrlf=false")
        .arg("-c")
        .arg("core.eol=lf")
        .arg("-c")
        .arg("diff.renames=false")
        .arg("-c")
        .arg("gc.auto=0")
        .args(arguments)
        .env("GIT_CONFIG_GLOBAL", &absent)
        .env("GIT_CONFIG_SYSTEM", &absent)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        // A system-wide gitattributes file can declare every file text and
        // rewrite its line endings, which would change the blob and with it
        // every id below it.
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", IDENTITY_NAME)
        .env("GIT_AUTHOR_EMAIL", IDENTITY_EMAIL)
        .env("GIT_COMMITTER_NAME", IDENTITY_NAME)
        .env("GIT_COMMITTER_EMAIL", IDENTITY_EMAIL)
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date);
    // Whatever repository the test runner itself is being run from must not be
    // the one that answers.
    for inherited in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CEILING_DIRECTORIES",
        "GIT_NAMESPACE",
        "GIT_TEMPLATE_DIR",
        "GIT_COMMON_DIR",
        "GIT_ATTR_FILE",
        // An object id is a hash, and which hash is a choice the environment
        // can otherwise make.
        "GIT_DEFAULT_HASH",
    ] {
        command.env_remove(inherited);
    }

    let spelled = || format!("git {}", arguments.join(" "));
    let output = command
        .output()
        .map_err(|source| FixtureError::GitUnavailable {
            command: spelled(),
            source,
        })?;
    if !output.status.success() {
        return Err(FixtureError::Git {
            command: spelled(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The one property everything built on this depends on. If two plantings
    /// of the same table can differ, every golden test reading a planted
    /// repository is measuring the machine it ran on.
    #[test]
    fn planting_the_same_history_twice_gives_the_same_commit_ids() {
        const HISTORY: [PlannedCommit; 3] = [
            PlannedCommit::writing("feat: begin", &[("src/lib.rs", "pub fn one() {}\n")]),
            PlannedCommit::writing(
                "fix: correct it",
                &[
                    ("src/lib.rs", "pub fn one() -> u8 { 1 }\n"),
                    ("docs/note.md", "why\n"),
                ],
            ),
            PlannedCommit::removing("refactor: drop the note", &["docs/note.md"]),
        ];

        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        plant(first.path(), &HISTORY).unwrap();
        plant(second.path(), &HISTORY).unwrap();

        let left = commit_ids(first.path()).unwrap();
        let right = commit_ids(second.path()).unwrap();
        assert_eq!(left.len(), HISTORY.len());
        assert_eq!(left, right);
        assert!(
            left.iter().all(|id| id.len() == 40),
            "a planted id is not a full object id: {left:?}"
        );
    }

    /// A held clock is what lets a test ask how commits sharing one second are
    /// ordered, so it has to actually hold.
    #[test]
    fn a_held_clock_dates_every_later_commit_the_same_second() {
        let repository = tempfile::tempdir().unwrap();
        let mut planter = Planter::initialise(repository.path()).unwrap();
        planter
            .commit(&PlannedCommit::writing("feat: one", &[("a.txt", "1\n")]))
            .unwrap();
        planter.hold_clock();
        planter
            .commit(&PlannedCommit::writing("feat: two", &[("b.txt", "2\n")]))
            .unwrap();
        planter
            .commit(&PlannedCommit::writing("feat: three", &[("c.txt", "3\n")]))
            .unwrap();

        let times = run(
            repository.path(),
            FIRST_COMMIT_TIME,
            &["log", "--reverse", "--format=%ct"],
        )
        .unwrap();
        assert_eq!(
            times.lines().collect::<Vec<_>>(),
            [
                FIRST_COMMIT_TIME.to_string(),
                (FIRST_COMMIT_TIME + COMMIT_INTERVAL).to_string(),
                (FIRST_COMMIT_TIME + COMMIT_INTERVAL).to_string(),
            ]
        );
    }

    /// A missing git binary and a failed command have to be told apart from a
    /// wrong answer, or a test that cannot run looks like a test that failed.
    #[test]
    fn a_failed_git_command_carries_what_git_said() {
        let repository = tempfile::tempdir().unwrap();
        let planter = Planter::initialise(repository.path()).unwrap();
        let error = planter
            .git(&["rev-parse", "--verify", "refs/heads/nothing"])
            .unwrap_err();
        let FixtureError::Git { stderr, status, .. } = &error else {
            unreachable!("{error:?}")
        };
        assert_ne!(*status, Some(0));
        assert!(!stderr.is_empty(), "git said nothing about the failure");
    }
}
