//! The unit of discovery: one physical source file.

use std::fmt;
use std::path::PathBuf;

use super::language::Language;

/// A stable content fingerprint of a file.
///
/// This hashes bytes only; it does not depend on line numbers, AST node ids or
/// any other position-derived value, so it is stable across reformatting that
/// leaves bytes unchanged and identical for two files with identical content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentHash(String);

impl ContentHash {
    /// Hash the given bytes.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(blake3::hash(bytes).to_hex().to_string())
    }

    /// The hash as a lowercase hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The role a source file plays in its package.
///
/// For Rust this is derived from the Cargo manifest and layout conventions; it
/// lets later stages down-weight test and example code without discarding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// Library sources (`src/lib.rs` and the module tree below it).
    Library,
    /// Binary sources (`src/main.rs`, `src/bin/`, or an explicit `[[bin]]`).
    Binary,
    /// Integration tests (`tests/`).
    Test,
    /// Benchmarks (`benches/`).
    Bench,
    /// Examples (`examples/`).
    Example,
    /// A Cargo build script (`build.rs`).
    BuildScript,
    /// Role could not be determined (for example, a C/C++ file outside any
    /// recognised package layout).
    Unknown,
}

impl TargetKind {
    /// Stable lowercase identifier used in reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Library => "library",
            Self::Binary => "binary",
            Self::Test => "test",
            Self::Bench => "bench",
            Self::Example => "example",
            Self::BuildScript => "build-script",
            Self::Unknown => "unknown",
        }
    }
}

/// One physical source file selected for analysis.
///
/// A file appears at most once: uniqueness is keyed on its normalized path, so
/// a header shared by several translation units is registered a single time.
/// [`content_hash`](Self::content_hash) additionally identifies byte-identical
/// copies at different paths.
#[derive(Debug, Clone)]
pub struct SourceUnit {
    /// Path relative to the scan root, used for display and stable ordering.
    pub relative_path: PathBuf,
    /// Absolute path, used to read the file.
    pub absolute_path: PathBuf,
    /// Detected language.
    pub language: Language,
    /// Whether the file is a header rather than a translation unit.
    pub is_header: bool,
    /// Content fingerprint.
    pub content_hash: ContentHash,
    /// File size in bytes.
    pub byte_len: u64,
    /// Owning Cargo package, when the file sits inside one.
    pub package: Option<String>,
    /// Role of the file in its package.
    pub target_kind: TargetKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_bytes_hash_equal_and_differ_from_others() {
        let a = ContentHash::of(b"fn main() {}");
        let b = ContentHash::of(b"fn main() {}");
        let c = ContentHash::of(b"fn main() { }");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_str().len(), 64);
    }

    #[test]
    fn target_kind_names_are_stable() {
        assert_eq!(TargetKind::Library.name(), "library");
        assert_eq!(TargetKind::BuildScript.name(), "build-script");
        assert_eq!(TargetKind::Unknown.name(), "unknown");
    }
}
