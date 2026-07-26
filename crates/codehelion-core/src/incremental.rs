//! What moved in the tree since the previous scan of it.
//!
//! Every discovered file already carries a [`ContentHash`] of its bytes, so
//! comparing two scans is comparing two path-to-hash maps. That is the whole
//! of change detection: a file is unchanged when its bytes hash the same, and
//! nothing else is consulted.
//!
//! # Why not modification times
//!
//! A timestamp says when a file was written, not whether writing it changed
//! anything, and it is wrong in both directions: a checkout rewrites every
//! mtime without changing a byte, and a restored backup can leave an older
//! mtime on newer content. Answering from the bytes costs a read the scan
//! performs anyway, and the answer is never a guess.
//!
//! # What a comparison is between
//!
//! Two scans are comparable when they looked at the same tree under the same
//! [`BuildVariant`](crate::discovery::BuildVariant). A file whose bytes did
//! not move still has to be re-analysed when the rules for analysing it did,
//! so pairing runs across variants would report "unchanged" about work that
//! has to happen again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crate::discovery::{ContentHash, SourceUnit};

/// The files a previous scan saw, by path relative to the scan root.
pub type PreviousFiles = BTreeMap<PathBuf, ContentHash>;

/// How one scan's files compare with a previous scan's.
///
/// The four sets partition the union of both scans' paths: every path appears
/// in exactly one of them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileChanges {
    /// Present in both scans, hashing the same.
    pub unchanged: Vec<PathBuf>,
    /// Present in both scans, hashing differently.
    pub modified: Vec<PathBuf>,
    /// Present in this scan only.
    pub added: Vec<PathBuf>,
    /// Present in the previous scan only.
    pub removed: Vec<PathBuf>,
}

impl FileChanges {
    /// Whether the two scans saw the same bytes at the same paths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.modified.is_empty() && self.added.is_empty() && self.removed.is_empty()
    }

    /// Files this scan has to analyse afresh: everything but the unchanged.
    ///
    /// Removed files are not here — there is nothing left to analyse — but
    /// they still have to be dropped from the index, which is the caller's
    /// business rather than this count's.
    #[must_use]
    pub fn to_analyse(&self) -> usize {
        self.modified.len() + self.added.len()
    }
}

/// Compare the files this scan discovered against what a previous scan saw.
///
/// `current` is expected in the order discovery produced, which is by path;
/// the output preserves it, so two runs over one tree describe it identically.
#[must_use]
pub fn compare(previous: &PreviousFiles, current: &[SourceUnit]) -> FileChanges {
    let mut changes = FileChanges::default();
    let mut seen: BTreeSet<&PathBuf> = BTreeSet::new();
    for unit in current {
        seen.insert(&unit.relative_path);
        match previous.get(&unit.relative_path) {
            Some(hash) if *hash == unit.content_hash => {
                changes.unchanged.push(unit.relative_path.clone());
            }
            Some(_) => changes.modified.push(unit.relative_path.clone()),
            None => changes.added.push(unit.relative_path.clone()),
        }
    }
    changes.removed = previous
        .keys()
        .filter(|path| !seen.contains(path))
        .cloned()
        .collect();
    changes
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::discovery::{Language, TargetKind};

    fn file(path: &str, content: &str) -> SourceUnit {
        SourceUnit {
            relative_path: PathBuf::from(path),
            absolute_path: PathBuf::from("/root").join(path),
            language: Language::Rust,
            is_header: false,
            content_hash: ContentHash::of(content.as_bytes()),
            byte_len: content.len() as u64,
            package: None,
            target_kind: TargetKind::Library,
        }
    }

    fn previous(entries: &[(&str, &str)]) -> PreviousFiles {
        entries
            .iter()
            .map(|(path, content)| (PathBuf::from(path), ContentHash::of(content.as_bytes())))
            .collect()
    }

    #[test]
    fn identical_trees_have_nothing_to_analyse() {
        let before = previous(&[("a.rs", "one"), ("b.rs", "two")]);
        let now = vec![file("a.rs", "one"), file("b.rs", "two")];

        let changes = compare(&before, &now);
        assert!(changes.is_empty());
        assert_eq!(changes.to_analyse(), 0);
        assert_eq!(changes.unchanged.len(), 2);
    }

    #[test]
    fn each_path_lands_in_exactly_one_set() {
        let before = previous(&[("kept.rs", "same"), ("edited.rs", "old"), ("gone.rs", "x")]);
        let now = vec![
            file("edited.rs", "new"),
            file("fresh.rs", "y"),
            file("kept.rs", "same"),
        ];

        let changes = compare(&before, &now);
        assert_eq!(changes.unchanged, vec![PathBuf::from("kept.rs")]);
        assert_eq!(changes.modified, vec![PathBuf::from("edited.rs")]);
        assert_eq!(changes.added, vec![PathBuf::from("fresh.rs")]);
        assert_eq!(changes.removed, vec![PathBuf::from("gone.rs")]);
        assert_eq!(changes.to_analyse(), 2);
    }

    #[test]
    fn a_file_moved_to_another_path_is_an_addition_and_a_removal() {
        // Identical bytes at a new path. Calling that a rename would be a
        // guess, and it is not one this stage has to make: both halves are
        // analysed afresh, and identical content reaches the same
        // fingerprints anyway.
        let before = previous(&[("old/name.rs", "body")]);
        let now = vec![file("new/name.rs", "body")];

        let changes = compare(&before, &now);
        assert_eq!(changes.added, vec![PathBuf::from("new/name.rs")]);
        assert_eq!(changes.removed, vec![PathBuf::from("old/name.rs")]);
        assert!(changes.unchanged.is_empty());
    }

    #[test]
    fn with_no_previous_scan_everything_is_new() {
        let now = vec![file("a.rs", "one"), file("b.rs", "two")];
        let changes = compare(&PreviousFiles::new(), &now);

        assert_eq!(changes.added.len(), 2);
        assert!(changes.unchanged.is_empty());
        assert!(!changes.is_empty(), "a first scan is not an unchanged tree");
    }

    #[test]
    fn an_emptied_tree_reports_every_file_removed() {
        let before = previous(&[("a.rs", "one"), ("b.rs", "two")]);
        let changes = compare(&before, &[]);

        assert_eq!(changes.removed.len(), 2);
        assert_eq!(changes.to_analyse(), 0, "nothing is left to read");
        assert!(!changes.is_empty());
    }
}
