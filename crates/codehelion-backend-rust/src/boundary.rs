//! The directory an untrusted request confines an answer to.
//!
//! A request carries one only for an untrusted scan, and what it says is that
//! the answer must be built out of files under it. Here that covers every path
//! this program resolves for itself: the file a request names, the manifest of
//! the package that file belongs to, and the workspace manifest the package is
//! read through. A project that reaches past the boundary is declined instead
//! of answered from a reading nobody bounded.
//!
//! It does not cover what Cargo and the analysis library go on to read once a
//! project inside the boundary has been accepted — a dependency resolved out of
//! the registry, the toolchain's own sysroot, the lockfile copy the load works
//! from. Those are reads of this machine's installation rather than of the tree
//! under analysis, and none of them is a path the tree chooses.

use std::path::{Path, PathBuf};

/// A directory every path an answer is built from has to resolve under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadBoundary(PathBuf);

impl ReadBoundary {
    /// The boundary at `directory`.
    ///
    /// A directory this machine does not hold keeps the spelling it arrived
    /// as, which no resolved path starts with: a boundary naming nothing holds
    /// nothing, and the requests made under it are declined rather than
    /// answered against a directory that is not there.
    pub(crate) fn new(directory: &Path) -> Self {
        Self(
            directory
                .canonicalize()
                .unwrap_or_else(|_| directory.to_path_buf()),
        )
    }

    /// Whether `path` resolves inside the boundary.
    ///
    /// Resolved before it is compared, so neither a link nor a `..` spelled
    /// inside the path decides the answer: a symbolic link planted in the tree
    /// under analysis is followed to where it points, and a path that climbs
    /// out and back in is judged where it lands. A path naming nothing is
    /// outside every boundary, because what it would resolve to is not
    /// knowable.
    ///
    /// Compared by component rather than by text, so a sibling whose name
    /// begins with the boundary's is not mistaken for something inside it.
    pub(crate) fn holds(&self, path: &Path) -> bool {
        path.canonicalize()
            .is_ok_and(|resolved| resolved.starts_with(&self.0))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::ReadBoundary;

    /// A tree with a directory inside the boundary and one beside it.
    fn tree() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("a temporary directory");
        for name in ["inside", "inside-out", "beside"] {
            std::fs::create_dir(directory.path().join(name)).expect("a directory");
            std::fs::write(directory.path().join(name).join("file.rs"), "").expect("a file in it");
        }
        directory
    }

    #[test]
    fn a_file_under_the_boundary_is_held() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(boundary.holds(&tree.path().join("inside/file.rs")));
    }

    #[test]
    fn a_file_beside_the_boundary_is_not_held() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(!boundary.holds(&tree.path().join("beside/file.rs")));
    }

    /// The name test: `inside-out` starts with `inside` as text and is no part
    /// of it as a directory.
    #[test]
    fn a_sibling_whose_name_begins_with_the_boundarys_is_not_held() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(!boundary.holds(&tree.path().join("inside-out/file.rs")));
    }

    #[test]
    fn a_path_that_climbs_out_and_back_in_is_held() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(boundary.holds(&tree.path().join("inside/../inside/file.rs")));
    }

    #[test]
    fn a_path_that_climbs_out_is_not_held() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(!boundary.holds(&tree.path().join("inside/../beside/file.rs")));
    }

    /// Following the link is the point: the boundary is about which files are
    /// read, and reading a link reads what it points at.
    #[test]
    #[cfg(unix)]
    fn a_link_pointing_outside_the_boundary_is_not_held() {
        let tree = tree();
        let link = tree.path().join("inside/elsewhere.rs");
        std::os::unix::fs::symlink(tree.path().join("beside/file.rs"), &link)
            .expect("linking out of the boundary");
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(!boundary.holds(&link));
    }

    #[test]
    fn a_boundary_naming_nothing_holds_nothing() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("no-such-directory"));
        assert!(!boundary.holds(&tree.path().join("inside/file.rs")));
    }

    #[test]
    fn a_file_that_is_not_there_is_held_by_no_boundary() {
        let tree = tree();
        let boundary = ReadBoundary::new(&tree.path().join("inside"));
        assert!(!boundary.holds(&tree.path().join("inside/absent.rs")));
    }
}
