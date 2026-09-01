//! Optional reading of a Clang `compile_commands.json` database.
//!
//! When present, the compilation database lists the C/C++ translation units and
//! their include directories. codehelion reads it only as a hint — discovery
//! works without it — and never invokes the recorded compiler commands.
//!
//! A translation unit is a file *and* the arguments it was compiled with, not a
//! file alone. The same header compiled under two sets of defines is two
//! translation units producing two different programs, and a database that
//! lists one file twice with different flags is describing exactly that. So
//! duplicates are removed by the whole command, and the count of distinct
//! source files is offered separately — that is the number the fragment side
//! wants, since a physical source region is registered once however many
//! compilations read it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use codehelion_helper_protocol::compile_commands::RecordedCommand;

use super::{BuildConfiguration, CppBuild};

/// A failure while reading the compilation database.
#[derive(Debug, thiserror::Error)]
pub enum CompileCommandsError {
    /// The file exceeds the configured input-size ceiling.
    #[error("compile_commands.json is {actual_bytes} bytes, exceeding the {max_bytes}-byte limit")]
    TooLarge {
        /// The observed byte length.
        actual_bytes: u64,
        /// The configured byte limit.
        max_bytes: u64,
    },
    /// The file could not be read.
    #[error("reading compile_commands.json: {0}")]
    Read(#[source] std::io::Error),
    /// The file was not valid JSON in the expected shape.
    #[error("parsing compile_commands.json: {0}")]
    Parse(#[source] serde_json::Error),
}

/// A single translation unit from the compilation database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileEntry {
    /// The translation unit's source path, resolved against its directory when
    /// the recorded path is relative.
    pub file: PathBuf,
    /// The working directory the command was recorded in, if any.
    pub directory: Option<PathBuf>,
    /// The compiler invocation, one argument per element.
    ///
    /// Empty for a database that recorded neither `arguments` nor `command`,
    /// which is legal and means only that this unit's build configuration is
    /// unknown — not that it was compiled with nothing.
    pub arguments: Vec<String>,
}

impl CompileEntry {
    /// The semantic build configuration this exact command describes.
    ///
    /// Database-wide text does not participate: unrelated commands and
    /// generator reformatting must not change this translation unit's build
    /// identity when its normalized compiler settings did not change.
    #[must_use]
    pub fn build(&self) -> CppBuild {
        CppBuild::from_command_in_directory(&self.arguments, &self.file, self.directory.as_deref())
    }

    /// The stable fields a helper uses to select this exact command.
    ///
    /// Paths are normalized in the same way as the helper's database reader,
    /// so a scan rooted through a symbolic link cannot accidentally turn one
    /// command into an unselectable sibling.
    #[must_use]
    pub fn selector_fields(&self) -> (String, Option<String>, Vec<String>) {
        let normalize = |path: &Path| {
            crate::paths::canonical(path)
                .unwrap_or_else(|_| path.to_path_buf())
                .display()
                .to_string()
        };
        (
            normalize(&self.file),
            self.directory.as_deref().map(normalize),
            self.arguments.clone(),
        )
    }
}

/// A parsed compilation database with duplicate translation units removed.
#[derive(Debug, Clone, Default)]
pub struct CompileCommands {
    /// Distinct translation units, in the order first seen.
    pub entries: Vec<CompileEntry>,
    /// A hash of the document this was read from, retained as provenance.
    ///
    /// Per-entry build identities use normalized compiler settings instead;
    /// this database-wide value would make an unrelated added translation
    /// unit invalidate every existing partition.
    pub content_hash: Option<String>,
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
        Self::parse(&text)
    }

    /// Read and parse a compilation database after enforcing `max_bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`CompileCommandsError::TooLarge`] before reading an oversized
    /// file, or the same failures as [`Self::read`] for an otherwise readable
    /// file.
    pub fn read_with_limit(path: &Path, max_bytes: u64) -> Result<Self, CompileCommandsError> {
        let metadata = std::fs::metadata(path).map_err(CompileCommandsError::Read)?;
        if metadata.len() > max_bytes {
            return Err(CompileCommandsError::TooLarge {
                actual_bytes: metadata.len(),
                max_bytes,
            });
        }
        let text = std::fs::read_to_string(path).map_err(CompileCommandsError::Read)?;
        if text.len() as u64 > max_bytes {
            return Err(CompileCommandsError::TooLarge {
                actual_bytes: text.len() as u64,
                max_bytes,
            });
        }
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, CompileCommandsError> {
        let raw: Vec<RecordedCommand> =
            serde_json::from_str(text).map_err(CompileCommandsError::Parse)?;
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        for entry in raw {
            // The words come from the reader both sides share, so the helper
            // that has to find this entry again splits its recorded command
            // exactly where this does.
            let arguments = entry.words().unwrap_or_default();
            // Both paths come from the reader both sides share for the same
            // reason the words do: where a recorded path is relative to is the
            // command's own directory, and one rule decides that.
            let resolved = entry.source();
            let directory = entry.directory.map(PathBuf::from);
            // The directory is part of what makes two commands one, because the
            // relative paths in them are read against it: one command run from
            // two build directories reads two sets of headers, and dropping the
            // second would leave a translation unit the run never accounts for.
            if seen.insert((resolved.clone(), directory.clone(), arguments.clone())) {
                entries.push(CompileEntry {
                    file: resolved,
                    directory,
                    arguments,
                });
            }
        }
        Ok(Self {
            entries,
            content_hash: Some(super::build_config::content_hash(text)),
        })
    }

    /// Number of distinct translation units.
    #[must_use]
    pub const fn translation_unit_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of distinct source files across those translation units.
    ///
    /// Lower than [`Self::translation_unit_count`] wherever a file is compiled
    /// more than one way, which is the case the fragment side has to avoid
    /// registering twice.
    #[must_use]
    pub fn source_file_count(&self) -> usize {
        self.entries
            .iter()
            .map(|entry| &entry.file)
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Group entries by the C/C++ build configuration they describe.
    ///
    /// A partition contains every command with identical semantic settings;
    /// source paths deliberately do not participate in its identity. That
    /// lets two ordinary translation units share one scan while keeping a
    /// duplicated source with different `-D` settings in separate partitions.
    #[must_use]
    pub fn build_partitions(&self) -> std::collections::BTreeMap<String, Vec<&CompileEntry>> {
        let mut partitions = std::collections::BTreeMap::new();
        for entry in &self.entries {
            let build = BuildConfiguration::Cpp(Box::new(entry.build()));
            partitions
                .entry(build.fingerprint())
                .or_insert_with(Vec::new)
                .push(entry);
        }
        partitions
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

    /// The case the C++ side exists to get right: one file, two compilations,
    /// two programs. Counting it as one translation unit would let a finding
    /// about the narrow build be reported against the wide one.
    #[test]
    fn one_file_compiled_two_ways_is_two_translation_units() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(
            &path,
            r#"[
                {"directory": "/w", "file": "/w/a.c", "arguments": ["cc", "-c", "/w/a.c"]},
                {"directory": "/w", "file": "/w/a.c",
                 "arguments": ["cc", "-DWIDE=1", "-c", "/w/a.c"]}
            ]"#,
        )
        .unwrap();
        let db = CompileCommands::read(&path).unwrap();
        assert_eq!(db.translation_unit_count(), 2);
        // And one physical file, which is what the fragment side registers.
        assert_eq!(db.source_file_count(), 1);
    }

    #[test]
    fn commands_partition_by_build_settings_not_source_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(
            &path,
            r#"[
                {"directory": "/w", "file": "/w/a.cpp", "arguments": ["clang++", "-DNARROW", "-c", "/w/a.cpp"]},
                {"directory": "/w", "file": "/w/b.cpp", "arguments": ["clang++", "-DNARROW", "-c", "/w/b.cpp"]},
                {"directory": "/w", "file": "/w/a.cpp", "arguments": ["clang++", "-DWIDE", "-c", "/w/a.cpp"]}
            ]"#,
        )
        .unwrap();
        let db = CompileCommands::read(&path).unwrap();
        let partitions = db.build_partitions();
        assert_eq!(partitions.len(), 2);
        let mut sizes: Vec<usize> = partitions.values().map(Vec::len).collect();
        sizes.sort_unstable();
        assert_eq!(sizes, [1, 2]);
        assert!(partitions.values().any(|entries| {
            entries
                .iter()
                .all(|entry| entry.build().defines() == ["NARROW"])
        }));
        assert!(partitions.values().any(|entries| {
            entries
                .iter()
                .all(|entry| entry.build().defines() == ["WIDE"])
        }));
    }

    /// Compilation databases normally spell each input relative to the command
    /// directory. Those input paths identify translation units, not builds.
    #[test]
    fn relative_source_arguments_do_not_split_an_otherwise_shared_build() {
        let dir = tempfile::tempdir().unwrap();
        let source_dir = dir.path().join("src");
        std::fs::create_dir_all(&source_dir).unwrap();
        std::fs::write(source_dir.join("first.cpp"), "int first() { return 1; }\n").unwrap();
        std::fs::write(
            source_dir.join("second.cpp"),
            "int second() { return 2; }\n",
        )
        .unwrap();
        let path = dir.path().join("compile_commands.json");
        // Quoted rather than pasted between quotation marks: a path is not made
        // only of characters JSON leaves alone, and on Windows every separator
        // in it reads as the start of an escape.
        let directory = serde_json::to_string(&source_dir.display().to_string()).unwrap();
        std::fs::write(
            &path,
            format!(
                r#"[
                    {{"directory": {directory}, "file": "first.cpp", "arguments": ["clang++", "-std=c++20", "-c", "first.cpp"]}},
                    {{"directory": {directory}, "file": "second.cpp", "arguments": ["clang++", "-std=c++20", "-c", "second.cpp"]}}
                ]"#
            ),
        )
        .unwrap();

        let db = CompileCommands::read(&path).unwrap();
        let partitions = db.build_partitions();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions.values().next().map(Vec::len), Some(2));
    }

    /// Two commands written word for word alike, run from two build
    /// directories, reading two different `include` directories. Reported as
    /// one partition, every clone found in it would be a claim about code that
    /// the project does not compile the same way.
    #[test]
    fn one_command_run_from_two_build_directories_is_two_builds() {
        let db = CompileCommands::parse(
            r#"[
                {"directory": "/w/one", "file": "/w/src/a.cpp",
                 "arguments": ["clang++", "-Iinclude", "-c", "/w/src/a.cpp"]},
                {"directory": "/w/two", "file": "/w/src/a.cpp",
                 "arguments": ["clang++", "-Iinclude", "-c", "/w/src/a.cpp"]}
            ]"#,
        )
        .unwrap();
        assert_eq!(db.translation_unit_count(), 2);
        let fingerprint =
            |entry: &CompileEntry| BuildConfiguration::Cpp(Box::new(entry.build())).fingerprint();
        assert_ne!(fingerprint(&db.entries[0]), fingerprint(&db.entries[1]));
        assert_eq!(db.build_partitions().len(), 2);
    }

    #[test]
    fn a_recorded_command_line_is_split_the_way_a_shell_would_split_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(
            &path,
            r#"[{"directory": "/w", "file": "/w/a.c",
                 "command": "cc -I\"/w/inc dir\" -DTEXT='a b' -c /w/a.c"}]"#,
        )
        .unwrap();
        let db = CompileCommands::read(&path).unwrap();
        assert_eq!(
            db.entries[0].arguments,
            vec!["cc", "-I/w/inc dir", "-DTEXT=a b", "-c", "/w/a.c"]
        );
    }

    /// The selector a helper is sent carries these words, and the helper finds
    /// the entry by comparing them exactly. They are produced by the shared
    /// reader on both sides, so a separator one side treats as spacing cannot
    /// leave the entry unfindable from the other.
    #[test]
    fn the_words_a_selector_carries_come_from_the_shared_reader() {
        let command = "cc -DTEXT='a b'\t-I/w/inc\n-c /w/a.c";
        let quoted = serde_json::to_string(command).unwrap();
        let db = CompileCommands::parse(&format!(
            r#"[{{"directory": "/w", "file": "/w/a.c", "command": {quoted}}}]"#
        ))
        .unwrap();
        let (_, _, arguments) = db.entries[0].selector_fields();
        assert_eq!(
            arguments,
            codehelion_helper_protocol::split_command(command)
        );
        assert_eq!(arguments, ["cc", "-DTEXT=a b", "-I/w/inc", "-c", "/w/a.c"]);
    }

    /// The database is where every unit's arguments come from, so two runs that
    /// read different databases were describing different builds.
    #[test]
    fn the_database_is_identified_by_what_it_says() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("one.json");
        let other = dir.path().join("other.json");
        std::fs::write(&one, r#"[{"directory": "/w", "file": "/w/a.c"}]"#).unwrap();
        std::fs::write(&other, r#"[{"directory": "/w", "file": "/w/b.c"}]"#).unwrap();
        let one = CompileCommands::read(&one).unwrap();
        let other = CompileCommands::read(&other).unwrap();
        assert!(one.content_hash.is_some());
        assert_ne!(one.content_hash, other.content_hash);
    }

    #[test]
    fn unrelated_database_entries_do_not_change_an_existing_partition_identity() {
        let one = CompileCommands::parse(
            r#"[{"directory":"/w","file":"/w/a.c","arguments":["cc","-DVALUE=1","-c","/w/a.c"]}]"#,
        )
        .unwrap();
        let expanded = CompileCommands::parse(
            r#"[
                {"directory":"/w","file":"/w/a.c","arguments":["cc","-DVALUE=1","-c","/w/a.c"]},
                {"directory":"/w","file":"/w/unrelated.c","arguments":["cc","-DVALUE=2","-c","/w/unrelated.c"]}
            ]"#,
        )
        .unwrap();

        let original = BuildConfiguration::Cpp(Box::new(one.entries[0].build())).fingerprint();
        let unchanged =
            BuildConfiguration::Cpp(Box::new(expanded.entries[0].build())).fingerprint();
        assert_eq!(original, unchanged);
        assert_ne!(one.content_hash, expanded.content_hash);
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

    #[test]
    fn a_database_over_the_size_limit_is_rejected_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("compile_commands.json");
        std::fs::write(&path, "[{}]").unwrap();

        assert!(matches!(
            CompileCommands::read_with_limit(&path, 2),
            Err(CompileCommandsError::TooLarge {
                actual_bytes: 4,
                max_bytes: 2,
            })
        ));
    }
}
