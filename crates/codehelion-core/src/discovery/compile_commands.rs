//! Optional reading of a Clang `compile_commands.json` database.
//!
//! When present, the compilation database lists the C/C++ translation units and
//! their include directories. codehelion reads it only as a hint — discovery
//! works without it — and never invokes the recorded compiler commands. Each
//! translation unit is registered once even if the database lists it several
//! times.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// A failure while reading the compilation database.
#[derive(Debug, thiserror::Error)]
pub enum CompileCommandsError {
    /// The file could not be read.
    #[error("reading compile_commands.json: {0}")]
    Read(#[source] std::io::Error),
    /// The file was not valid JSON in the expected shape.
    #[error("parsing compile_commands.json: {0}")]
    Parse(#[source] serde_json::Error),
}

#[derive(Debug, Deserialize)]
struct RawEntry {
    file: String,
    directory: Option<String>,
}

/// A single translation unit from the compilation database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileEntry {
    /// The translation unit's source path, resolved against its directory when
    /// the recorded path is relative.
    pub file: PathBuf,
    /// The working directory the command was recorded in, if any.
    pub directory: Option<PathBuf>,
}

/// A parsed compilation database with duplicate translation units removed.
#[derive(Debug, Clone, Default)]
pub struct CompileCommands {
    /// Distinct translation units, in the order first seen.
    pub entries: Vec<CompileEntry>,
}

impl CompileCommands {
    /// Read and parse a `compile_commands.json` file at `path`.
    ///
    /// # Errors
    ///
    /// Returns [`CompileCommandsError`] if the file cannot be read or is not a
    /// JSON array of `{ "file": ..., "directory": ... }` objects.
    pub fn read(path: &Path) -> Result<Self, CompileCommandsError> {
        let text = std::fs::read_to_string(path).map_err(CompileCommandsError::Read)?;
        let raw: Vec<RawEntry> =
            serde_json::from_str(&text).map_err(CompileCommandsError::Parse)?;
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        for entry in raw {
            let directory = entry.directory.map(PathBuf::from);
            let file_path = PathBuf::from(&entry.file);
            let resolved = match (&directory, file_path.is_relative()) {
                (Some(dir), true) => dir.join(&file_path),
                _ => file_path,
            };
            if seen.insert(resolved.clone()) {
                entries.push(CompileEntry {
                    file: resolved,
                    directory,
                });
            }
        }
        Ok(Self { entries })
    }

    /// Number of distinct translation units.
    #[must_use]
    pub fn translation_unit_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_entries_and_resolves_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(
            &path,
            r#"[
                {"directory": "/work/build", "file": "../src/a.c", "command": "cc a.c"},
                {"directory": "/work/build", "file": "/abs/b.c", "command": "cc b.c"}
            ]"#,
        )
        .unwrap();
        let db = CompileCommands::read(&path).unwrap();
        assert_eq!(db.translation_unit_count(), 2);
        assert_eq!(db.entries[0].file, PathBuf::from("/work/build/../src/a.c"));
        assert_eq!(db.entries[1].file, PathBuf::from("/abs/b.c"));
    }

    #[test]
    fn duplicate_translation_units_are_registered_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(
            &path,
            r#"[
                {"directory": "/w", "file": "/w/a.c"},
                {"directory": "/w", "file": "/w/a.c"}
            ]"#,
        )
        .unwrap();
        let db = CompileCommands::read(&path).unwrap();
        assert_eq!(db.translation_unit_count(), 1);
    }

    #[test]
    fn malformed_json_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(&path, "not json").unwrap();
        assert!(matches!(
            CompileCommands::read(&path),
            Err(CompileCommandsError::Parse(_))
        ));
    }
}
