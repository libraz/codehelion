//! The compilation database, which is the only thing that says how a C or C++
//! file is compiled.
//!
//! A C++ source file on its own says almost nothing about the program it
//! becomes. The macros defined on the command line decide which branches of
//! every header it includes exist at all, and the include path decides which
//! file a quoted name even resolves to. Two translation units can include one
//! header and get two different programs out of it — the fixtures in this
//! repository are exactly that — so a helper that analysed a file without its
//! command would be reporting one of the possible readings and calling it the
//! reading.
//!
//! # Nothing here runs anything
//!
//! The database is read where it already is. This program never runs the
//! commands it lists, and never runs the generator that would produce one:
//! configuring a build is running the project's code, and a C++ project's
//! configure step is a program the project ships. A tree with no database is a
//! tree this helper cannot answer about, which it says rather than fixes.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Where a database can sit relative to the directory a project is rooted at.
///
/// The build directory is listed because that is where the generator writes it
/// and it is the usual arrangement; the root is listed because that is where
/// people symlink it to so their editor finds it.
const LOCATIONS: [&str; 2] = ["compile_commands.json", "build/compile_commands.json"];

/// One translation unit, as the database describes it.
pub(crate) struct Entry {
    /// The source it is compiled from.
    pub(crate) file: PathBuf,
    /// The arguments to parse it with: the recorded invocation without its
    /// compiler, its input, or where it was to write its output.
    pub(crate) arguments: Vec<String>,
    /// The macros defined on the command line, as the flags spelled them.
    pub(crate) definitions: Vec<String>,
}

/// A compilation database, and the directory a project rooted at it spells its
/// files against.
pub(crate) struct Database {
    /// The directory the search found the database from, which is the project
    /// root rather than wherever the file itself landed: a database under
    /// `build/` describes the tree above it, and anchoring the answers at the
    /// build directory would spell every source file as `../src/...`.
    pub(crate) root: PathBuf,
    /// One entry per translation unit, in the order the database lists them.
    pub(crate) entries: Vec<Entry>,
}

impl Database {
    /// The database governing `path`, found by walking up from it.
    ///
    /// `None` when there is none, which is a tree this helper has nothing to
    /// say about rather than a failure: a project that is entirely Rust has no
    /// compilation database and is not missing one.
    pub(crate) fn nearest(path: &Path) -> Option<Self> {
        let start = if path.is_dir() { path } else { path.parent()? };
        for ancestor in start.ancestors() {
            for location in LOCATIONS {
                let candidate = ancestor.join(location);
                if !candidate.is_file() {
                    continue;
                }
                // A database that is there and unreadable stops the search
                // rather than letting it walk further up: the answer for this
                // project is the file that was found, and finding somebody
                // else's higher up would analyse this tree under another
                // project's commands.
                return Self::read(&candidate, ancestor).ok();
            }
        }
        None
    }

    /// Read the database at `path`, spelling its answers against `root`.
    fn read(path: &Path, root: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("reading {}: {error}", path.display()))?;
        let raw: Vec<RawEntry> = serde_json::from_str(&text)
            .map_err(|error| format!("parsing {}: {error}", path.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
            entries: raw.iter().filter_map(RawEntry::entry).collect(),
        })
    }

    /// The entry for the translation unit spelled `unit`, against this root.
    pub(crate) fn unit(&self, unit: &str) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| codehelion_helper::ir::spell(Some(&self.root), &entry.file) == unit)
    }

    /// Every macro the database defines anywhere, sorted and without repeats.
    ///
    /// A run-level answer to a per-unit question, and deliberately so: this is
    /// what says the tree was read under these conditions somewhere in it,
    /// which is what a scan of the whole tree is. Which unit had which is
    /// carried by the unit's own build variant, where it decides something.
    pub(crate) fn definitions(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .entries
            .iter()
            .flat_map(|entry| entry.definitions.iter().cloned())
            .collect();
        all.sort();
        all.dedup();
        all
    }
}

/// One entry as the format writes it.
#[derive(Debug, Deserialize)]
struct RawEntry {
    file: String,
    directory: Option<String>,
    /// The invocation already split, which is the spelling that needs no
    /// guessing about quoting.
    #[serde(default)]
    arguments: Option<Vec<String>>,
    /// The invocation as one line, which generators still write.
    #[serde(default)]
    command: Option<String>,
}

impl RawEntry {
    /// This entry in the shape the rest of the helper uses, or nothing when it
    /// carries no command to read.
    fn entry(&self) -> Option<Entry> {
        let directory = self.directory.as_ref().map(PathBuf::from);
        let file = resolve(directory.as_deref(), Path::new(&self.file));
        let words = match (&self.arguments, &self.command) {
            (Some(arguments), _) => arguments.clone(),
            (None, Some(command)) => split(command),
            (None, None) => return None,
        };
        let mut entry = Entry {
            file,
            arguments: Vec::new(),
            definitions: Vec::new(),
        };
        entry.arguments = parse_arguments(&words, &entry.file, directory.as_deref());
        entry.definitions = definitions(&words);
        Some(entry)
    }
}

/// `path` made absolute against `directory` when it is not already.
fn resolve(directory: Option<&Path>, path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    directory.map_or_else(|| path.to_path_buf(), |directory| directory.join(path))
}

/// The recorded invocation as arguments a parser can be given.
///
/// The compiler, the input file and where the object file was to go are
/// dropped: the first is chosen by this helper rather than the project, and the
/// other two say which unit this is rather than how it is read. Everything else
/// is kept, including flags this helper does not understand — a flag that
/// changes what a header declares is not something to be filtered by taste.
fn parse_arguments(words: &[String], file: &Path, directory: Option<&Path>) -> Vec<String> {
    let mut arguments = Vec::new();
    // Relative include paths in a database are relative to the directory the
    // command was to run in, which is not this process's. Said once here so
    // that every path in the command resolves the way the build resolved it.
    if let Some(directory) = directory {
        arguments.push(format!("-working-directory={}", directory.display()));
    }
    let mut index = 1;
    while index < words.len() {
        let word = words[index].as_str();
        index += 1;
        if resolve(directory, Path::new(word)) == file {
            continue;
        }
        if DROPPED_WITH_VALUE.contains(&word) {
            index += 1;
            continue;
        }
        if DROPPED.contains(&word) || word.starts_with("-o") && word.len() > 2 {
            continue;
        }
        arguments.push(word.to_string());
    }
    arguments
}

/// Flags that say where output goes rather than how input is read.
const DROPPED: [&str; 5] = ["-c", "-MD", "-MMD", "-M", "-MM"];

/// The same, for the ones that take a separate value.
const DROPPED_WITH_VALUE: [&str; 4] = ["-o", "-MF", "-MT", "-MQ"];

/// Every macro the command defines or undefines, in the flag's own spelling.
fn definitions(words: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    let mut index = 0;
    while index < words.len() {
        let word = words[index].as_str();
        index += 1;
        for flag in ["-D", "-U"] {
            if word == flag {
                if let Some(value) = words.get(index) {
                    found.push(format!("{flag}{value}"));
                    index += 1;
                }
            } else if let Some(value) = word.strip_prefix(flag)
                && !value.is_empty()
            {
                found.push(format!("{flag}{value}"));
            }
        }
    }
    found
}

/// Split a recorded command line into words.
///
/// Quoting and backslash escaping only. A database that writes its commands as
/// one string has already lost whatever the shell would have done with them,
/// and guessing at expansion here would invent arguments no compiler was given.
fn split(command: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut escaped = false;
    for character in command.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            continue;
        }
        match (character, quote) {
            ('\\', None | Some('"')) => escaped = true,
            ('"' | '\'', None) => {
                quote = Some(character);
                started = true;
            }
            (_, Some(open)) if character == open => quote = None,
            (' ' | '\t', None) => {
                if started || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            _ => word.push(character),
        }
    }
    if started || !word.is_empty() {
        words.push(word);
    }
    words
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn words(command: &str) -> Vec<String> {
        split(command)
    }

    #[test]
    fn a_command_written_as_one_line_is_split_the_way_a_shell_would() {
        assert_eq!(words("clang++ -c a.cpp"), ["clang++", "-c", "a.cpp"]);
        assert_eq!(
            words(r#"clang++ -I"/o p/inc" -DA=\"x\" a.cpp"#),
            ["clang++", "-I/o p/inc", r#"-DA="x""#, "a.cpp"]
        );
        // An empty quoted argument is an argument, not nothing: `-DA=` and no
        // `-D` at all are different commands.
        assert_eq!(words(r#"clang++ "" a.cpp"#), ["clang++", "", "a.cpp"]);
    }

    #[test]
    fn what_a_unit_is_compiled_with_is_kept_and_where_it_writes_is_not() {
        let entry = RawEntry {
            file: "src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: Some(
                [
                    "clang++",
                    "-std=c++17",
                    "-DWIDE=64",
                    "-I../include",
                    "-c",
                    "-o",
                    "a.o",
                    "src/a.cpp",
                ]
                .map(str::to_string)
                .to_vec(),
            ),
            command: None,
        }
        .entry()
        .expect("the entry carries a command");

        assert_eq!(entry.file, Path::new("/work/build/src/a.cpp"));
        assert_eq!(
            entry.arguments,
            [
                "-working-directory=/work/build",
                "-std=c++17",
                "-DWIDE=64",
                "-I../include",
            ]
        );
        assert_eq!(entry.definitions, ["-DWIDE=64"]);
    }

    /// The relative include path in the entry above is relative to the
    /// directory the command was to run in, which is never this process's. A
    /// helper that dropped that would resolve `../include` against wherever a
    /// scan happened to be started and read a different header, or none.
    #[test]
    fn a_command_is_read_from_the_directory_it_was_to_run_in() {
        let entry = RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: Some(
                ["clang++", "-I../include", "/work/src/a.cpp"]
                    .map(str::to_string)
                    .to_vec(),
            ),
            command: None,
        }
        .entry()
        .expect("the entry carries a command");
        assert_eq!(
            entry.arguments.first().map(String::as_str),
            Some("-working-directory=/work/build")
        );
    }

    #[test]
    fn a_definition_is_collected_however_the_flag_spells_it() {
        let joined = ["-DA", "-DB=2", "-U", "C", "-D", "E=5", "-Iwherever"].map(str::to_string);
        assert_eq!(definitions(&joined), ["-DA", "-DB=2", "-UC", "-DE=5"]);
    }

    /// An entry with neither form of command describes no compilation, and a
    /// unit invented from one would be analysed with no flags at all — which is
    /// a different program from the one the project builds.
    #[test]
    fn an_entry_that_records_no_command_is_not_a_translation_unit() {
        assert!(
            RawEntry {
                file: "src/a.cpp".to_string(),
                directory: None,
                arguments: None,
                command: None,
            }
            .entry()
            .is_none()
        );
    }
}
