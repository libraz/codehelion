//! Reading a file whose name and kind the scanned tree controls.
//!
//! The scanner, the compiler helpers and the store each read files a
//! repository can plant: a lockfile, a manifest, a Cargo configuration, a
//! compilation database, a database sidecar. A planted FIFO blocks an open
//! forever, a link can point at `/dev/zero` or out of the tree, and an ordinary
//! file can be as large as the repository likes. One reader refuses all three
//! the same way, and it lives here because this is the one crate every reader
//! of the tree already depends on.
//!
//! The kind is decided before the file is opened and checked again on the
//! opened handle, so a swap between the two is caught. Whether a link counts is
//! the caller's [`Links`] choice, because some of these files are links by
//! convention. The size is checked before the first byte is read and again
//! while reading, so a file that grows under the reader stops at the ceiling.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// Whether a link to a regular file is read as that file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Links {
    /// A link is refused like any other file that is not regular.
    Refuse,
    /// A link is followed, and what it names must be a regular file.
    Follow,
}

/// Why a tree-supplied file was not read.
#[derive(Debug, thiserror::Error)]
pub enum TreeFileError {
    /// It is a link, a directory, a FIFO, a device or anything else that is not
    /// a regular file.
    #[error("it is not a regular file")]
    NotRegular,
    /// It holds more than the ceiling allows.
    #[error("it is larger than the {max_bytes}-byte limit")]
    TooLarge {
        /// The ceiling it exceeded.
        max_bytes: u64,
    },
    /// Its bytes are not UTF-8, where text was asked for.
    #[error("it is not UTF-8 text")]
    NotText,
    /// The operating system could not open or read it.
    #[error("{0}")]
    Io(#[source] std::io::Error),
}

impl TreeFileError {
    /// Whether the file is simply not there.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::Io(error) if error.kind() == std::io::ErrorKind::NotFound)
    }
}

/// Copy the regular file at `path` into `sink`, refusing anything else and
/// anything over `max_bytes`, and return how many bytes were copied.
///
/// A link is refused or followed as `links` says.
///
/// On [`TreeFileError::TooLarge`] at most `max_bytes + 1` bytes have reached
/// `sink`; a caller writing to a file of its own discards it.
///
/// # Errors
///
/// [`TreeFileError::NotRegular`] for any non-regular file,
/// [`TreeFileError::TooLarge`] past the ceiling, and [`TreeFileError::Io`] when
/// the file cannot be opened or read — including when it does not exist.
pub fn read_regular_bounded(
    path: &Path,
    links: Links,
    max_bytes: u64,
    sink: &mut impl Write,
) -> Result<u64, TreeFileError> {
    let named = match links {
        Links::Refuse => std::fs::symlink_metadata(path),
        Links::Follow => std::fs::metadata(path),
    }
    .map_err(TreeFileError::Io)?;
    if !named.file_type().is_file() {
        return Err(TreeFileError::NotRegular);
    }
    if named.len() > max_bytes {
        return Err(TreeFileError::TooLarge { max_bytes });
    }
    let file = File::open(path).map_err(TreeFileError::Io)?;
    let opened = file.metadata().map_err(TreeFileError::Io)?;
    if !opened.file_type().is_file() {
        return Err(TreeFileError::NotRegular);
    }
    let copied = std::io::copy(&mut file.take(max_bytes.saturating_add(1)), sink)
        .map_err(TreeFileError::Io)?;
    if copied > max_bytes {
        return Err(TreeFileError::TooLarge { max_bytes });
    }
    Ok(copied)
}

/// The regular file at `path` as text, under the same refusals as
/// [`read_regular_bounded`].
///
/// # Errors
///
/// As [`read_regular_bounded`], and [`TreeFileError::NotText`] when the bytes
/// are not UTF-8.
pub fn read_text_bounded(
    path: &Path,
    links: Links,
    max_bytes: u64,
) -> Result<String, TreeFileError> {
    let mut bytes = Vec::new();
    read_regular_bounded(path, links, max_bytes, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| TreeFileError::NotText)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_regular_file_within_the_ceiling_is_read_whole() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("Cargo.lock");
        std::fs::write(&path, "version = 4\n").unwrap();
        assert_eq!(
            read_text_bounded(&path, Links::Refuse, 12).unwrap(),
            "version = 4\n"
        );
    }

    #[test]
    fn a_file_over_the_ceiling_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("compile_commands.json");
        std::fs::write(&path, "x".repeat(64)).unwrap();
        let mut sink = Vec::new();
        assert!(matches!(
            read_regular_bounded(&path, Links::Refuse, 63, &mut sink),
            Err(TreeFileError::TooLarge { max_bytes: 63 })
        ));
        assert!(sink.is_empty(), "the size is checked before reading");
    }

    #[test]
    fn a_directory_is_not_a_regular_file() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_text_bounded(directory.path(), Links::Follow, u64::MAX),
            Err(TreeFileError::NotRegular)
        ));
    }

    #[test]
    fn a_missing_file_is_reported_as_not_found() {
        let directory = tempfile::tempdir().unwrap();
        let error = read_text_bounded(&directory.path().join("absent"), Links::Refuse, u64::MAX)
            .unwrap_err();
        assert!(error.is_not_found(), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_link_is_refused_or_followed_as_the_caller_says() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, "content").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            read_text_bounded(&link, Links::Refuse, u64::MAX),
            Err(TreeFileError::NotRegular)
        ));
        assert_eq!(
            read_text_bounded(&link, Links::Follow, u64::MAX).unwrap(),
            "content"
        );
    }
}
