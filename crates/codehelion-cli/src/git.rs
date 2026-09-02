//! The enclosing git repository, as the hints that mention it read it.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares one repository walk across the crate"
)]

use std::path::{Path, PathBuf};

/// The enclosing git repository root, found by walking up for a `.git` entry.
///
/// This is the single walk every caller shares, including
/// [`scan::runtime`](crate::scan::runtime)'s default database placement, which
/// wraps this with its own fallback for the no-`.git` case rather than
/// repeating the walk. Keeping the walk itself in exactly one place means
/// every caller either sees the same `.git` ancestor or none — they cannot
/// silently disagree about which directory it is.
///
/// What this directory is *not* is a confinement boundary. It is found by
/// inspecting the tree rather than named by the operator, so it can sit above
/// the directory the operator pointed at; a path a configuration chose is held
/// to `--path` instead. See [`provenance`](crate::provenance).
pub(crate) fn find_git_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    while let Some(current) = dir {
        if current.join(".git").exists() {
            return Some(current.to_path_buf());
        }
        dir = current.parent();
    }
    None
}

/// Whether the repository root's `.gitignore` ignores `target`.
///
/// Only the root ignore file is consulted — this backs a hint, not an access
/// decision. Paths outside the repository are reported as ignored so the
/// hint stays quiet about them.
pub(crate) fn is_git_ignored(repo_root: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(repo_root) else {
        return true;
    };
    let (gitignore, _error) = ignore::gitignore::Gitignore::new(repo_root.join(".gitignore"));
    gitignore
        .matched_path_or_any_parents(relative, false)
        .is_ignore()
}

/// Covers [`find_git_root`], the single walk that
/// [`scan::runtime`](crate::scan::runtime)'s default database placement and
/// the `.gitignore` hints in `doctor`/`scan` all share.
#[cfg(test)]
#[allow(clippy::expect_used)]
mod git_root_tests {
    use super::find_git_root;

    #[test]
    fn finds_the_nearest_ancestor_holding_a_dot_git_entry() {
        let repository = tempfile::tempdir().expect("create repository directory");
        std::fs::create_dir(repository.path().join(".git")).expect("create .git marker");
        let nested = repository.path().join("crates/inner");
        std::fs::create_dir_all(&nested).expect("create nested working directory");

        assert_eq!(
            find_git_root(&nested),
            Some(repository.path().to_path_buf())
        );
    }

    #[test]
    fn finds_nothing_above_a_tree_with_no_dot_git_ancestor() {
        let outside = tempfile::tempdir().expect("create directory outside any repository");

        assert_eq!(find_git_root(outside.path()), None);
    }
}
