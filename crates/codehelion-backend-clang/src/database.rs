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

use std::path::{Component, Path, PathBuf};

use codehelion_helper::CompileCommandSelector;
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
    /// The complete database identity used to select this entry.
    pub(crate) selector: CompileCommandSelector,
}

impl Entry {
    /// Arguments safe for the helper-owned syntax-only CFG frontend.
    ///
    /// Build commands can ask a compiler to load code, re-expand response
    /// files, or write an output. The CFG reader neither needs nor permits
    /// any of those. Refusing the entire auxiliary reading is deliberate: a
    /// command whose nested arguments are not known safe must not become safe
    /// by selectively guessing which pieces to retain.
    pub(crate) fn cfg_arguments(&self) -> Result<Vec<String>, String> {
        let mut safe = Vec::with_capacity(self.arguments.len());
        for argument in &self.arguments {
            if is_unsafe_for_cfg(argument) {
                return Err(format!(
                    "unsafe compiler argument for CFG frontend: {argument}"
                ));
            }
            safe.push(argument.clone());
        }
        Ok(safe)
    }
}

/// Whether an argument could make the fixed syntax-only command load code,
/// perform another command-line parse, or write an auxiliary artifact.
///
/// This is intentionally a deny list with a fail-closed response for every
/// Clang escape hatch. Normal preprocessing, include and language options are
/// retained because changing them would analyse a different program.
fn is_unsafe_for_cfg(argument: &str) -> bool {
    argument.starts_with('@')
        || matches!(
            argument,
            "-Xclang" | "-cc1" | "-mllvm" | "-load" | "-plugin"
        )
        || argument.starts_with("-Xclang=")
        || argument.starts_with("-cc1")
        || argument.starts_with("-mllvm")
        || argument.starts_with("-load")
        || argument.starts_with("-plugin")
        || argument.starts_with("-fplugin")
        || argument.starts_with("-fpass-plugin")
        || argument.starts_with("-analyzer-")
        || argument.starts_with("-fmodules")
        || argument.starts_with("-fmodule-")
        || argument.starts_with("-fimplicit-module")
        || argument.starts_with("-include-pch")
        || argument.starts_with("-emit-pch")
        || argument.starts_with("-emit-module")
        || argument.starts_with("-fmodule-output")
        || argument.starts_with("-fmodule-cache-path")
        || argument.starts_with("-save-temps")
        || argument.starts_with("-serialize-diagnostics")
        || argument.starts_with("-fdiagnostics-serialize-file")
        || argument.starts_with("-ftime-trace")
        || argument.starts_with("-MJ")
        || argument.starts_with("-E")
        || argument.starts_with("-S")
        || argument.starts_with("-emit-")
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
            // Resolved for the same reason the entries are: the root is what
            // every answer is spelled against, and one spelled against a root
            // the caller reached another way is a set of relative paths that
            // point somewhere else.
            root: canonical(root),
            entries: raw.iter().filter_map(RawEntry::entry).collect(),
        })
    }

    /// The entry for the translation unit named `unit`.
    ///
    /// Named either the way this project spells its files or by where the file
    /// is, because the two sides of a request need not stand in the same place:
    /// a scan rooted inside a tree spells a file against its own root, which is
    /// not the root the database was found from, and a name matched only one
    /// way would come back unanswerable for every unit of a project scanned
    /// from a subdirectory.
    ///
    /// Both spellings are compared as paths rather than as strings. A generator
    /// writes `src/a.cpp` on every platform while a path rebuilt here carries
    /// the separator the platform uses, and on Windows the two name one file
    /// that no string comparison calls equal.
    pub(crate) fn unit(
        &self,
        unit: &str,
        selector: Option<&CompileCommandSelector>,
    ) -> Option<&Entry> {
        let named = Path::new(unit);
        let absolute = canonical(named);
        self.entries.iter().find(|entry| {
            selector.is_none_or(|wanted| entry.selector == *wanted)
                && (Path::new(&codehelion_helper::ir::spell(Some(&self.root), &entry.file))
                    == named
                    || entry.file == absolute)
        })
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
        let written = resolve(directory.as_deref(), Path::new(&self.file));
        let words = match (&self.arguments, &self.command) {
            (Some(arguments), _) => arguments.clone(),
            (None, Some(command)) => split(command),
            (None, None) => return None,
        };
        // Resolved, because a generator run from a build directory writes its
        // sources as `../src/a.cpp` while a caller naming the same file names
        // it as it is. The two are one file and no plain string comparison
        // says so.
        let file = canonical(&written);
        let mut entry = Entry {
            file: file.clone(),
            arguments: Vec::new(),
            definitions: Vec::new(),
            selector: CompileCommandSelector {
                file: file.display().to_string(),
                directory: directory
                    .as_ref()
                    .map(|path| canonical(path).display().to_string()),
                arguments: words.clone(),
            },
        };
        // Matched against the path as the command spells it rather than as the
        // filesystem does: the argument to drop is the one the command carries,
        // and asking the filesystem about every other argument to find it would
        // be a search for something already in hand.
        entry.arguments = parse_arguments(&words, &written, directory.as_deref());
        entry.definitions = definitions(&words);
        Some(entry)
    }
}

/// `path` as the filesystem spells it, or with its `.` and `..` folded away
/// when it names nothing there.
///
/// Both sides of a request name files, and the two need not have arrived at
/// their spelling the same way: a scan resolves the root it was pointed at, a
/// generator writes whatever it was run with, and on a machine where the one is
/// reached through a symbolic link the two strings differ while the file is one
/// file. Asking the filesystem is the only thing that says so.
pub(crate) fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| lexical(path))
}

/// `path` with its `.` and `..` folded away.
///
/// The fallback for a path that names nothing, and the answer for the paths a
/// compiler reports back: those are built from an include search path and reach
/// this program by the thousand, which is too many to ask the filesystem about
/// one at a time.
pub(crate) fn lexical(path: &Path) -> PathBuf {
    let mut folded = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            // Only where there is something to fold: a leading `..` names a
            // directory the path does not otherwise mention, and dropping it
            // would name a different one.
            Component::ParentDir
                if folded
                    .components()
                    .next_back()
                    .is_some_and(|last| matches!(last, Component::Normal(_))) =>
            {
                folded.pop();
            }
            other => folded.push(other),
        }
    }
    folded
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

    #[test]
    fn cfg_frontend_refuses_plugin_and_clang_internal_execution_flags() {
        let entry = Entry {
            file: PathBuf::from("/work/src/a.cpp"),
            arguments: [
                "-std=c++20",
                "-Xclang",
                "-load",
                "-fplugin=/work/plugin.so",
                "-fplugin-arg-test=value",
                "-I/work/include",
            ]
            .map(str::to_string)
            .to_vec(),
            definitions: Vec::new(),
            selector: CompileCommandSelector {
                file: "/work/src/a.cpp".to_string(),
                directory: None,
                arguments: Vec::new(),
            },
        };
        assert!(entry.cfg_arguments().is_err());
    }

    #[test]
    fn cfg_frontend_retains_the_build_reading_when_it_is_syntax_only_safe() {
        let entry = Entry {
            file: PathBuf::from("/work/src/a.cpp"),
            arguments: [
                "-working-directory=/work/build",
                "-std=c++20",
                "-DLEVEL=2",
                "-I/work/include",
            ]
            .map(str::to_string)
            .to_vec(),
            definitions: Vec::new(),
            selector: CompileCommandSelector {
                file: "/work/src/a.cpp".to_string(),
                directory: None,
                arguments: Vec::new(),
            },
        };
        assert_eq!(
            entry
                .cfg_arguments()
                .expect("ordinary parsing flags are safe"),
            [
                "-working-directory=/work/build",
                "-std=c++20",
                "-DLEVEL=2",
                "-I/work/include",
            ]
        );
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

    /// The caller and the database need not stand in the same place. A scan
    /// rooted inside a tree spells its files against its own root, which is not
    /// the one this database was found from, so a unit is found by where it is
    /// as well as by how this project spells it.
    #[test]
    fn a_unit_is_found_by_where_it_is_as_well_as_by_how_the_project_spells_it() {
        let database = Database {
            root: PathBuf::from("/work"),
            entries: vec![
                RawEntry {
                    file: "/work/src/a.cpp".to_string(),
                    directory: Some("/work/build".to_string()),
                    arguments: Some(
                        ["clang++", "-std=c++17", "/work/src/a.cpp"]
                            .map(str::to_string)
                            .to_vec(),
                    ),
                    command: None,
                }
                .entry()
                .expect("the entry carries a command"),
            ],
        };
        assert!(database.unit("src/a.cpp", None).is_some());
        assert!(database.unit("/work/src/a.cpp", None).is_some());
        // A file this database says nothing about stays unanswerable, whichever
        // way it is named: finding the nearest entry would analyse one unit and
        // report it as another.
        assert!(database.unit("/work/src/b.cpp", None).is_none());
        assert!(database.unit("src/b.cpp", None).is_none());
    }

    #[test]
    fn an_exact_selector_never_falls_back_to_another_command_for_the_same_file() {
        let narrow = RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work".to_string()),
            arguments: Some(
                ["clang++", "-DNARROW", "-c", "/work/src/a.cpp"]
                    .map(str::to_string)
                    .to_vec(),
            ),
            command: None,
        }
        .entry()
        .expect("the entry carries a command");
        let wide = RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work".to_string()),
            arguments: Some(
                ["clang++", "-DWIDE", "-c", "/work/src/a.cpp"]
                    .map(str::to_string)
                    .to_vec(),
            ),
            command: None,
        }
        .entry()
        .expect("the entry carries a command");
        let database = Database {
            root: PathBuf::from("/work"),
            entries: vec![narrow, wide],
        };
        let wide_selector = database.entries[1].selector.clone();
        let selected = database
            .unit("/work/src/a.cpp", Some(&wide_selector))
            .expect("the requested command is present");
        assert_eq!(selected.selector, wide_selector);
        let missing = CompileCommandSelector {
            arguments: vec!["clang++".to_string(), "-DOTHER".to_string()],
            ..wide_selector
        };
        assert!(database.unit("/work/src/a.cpp", Some(&missing)).is_none());
    }

    /// A generator run from a build directory names its sources through the
    /// directory above. That is the same file a caller names directly, and a
    /// comparison of the two spellings as text says it is not.
    #[test]
    fn a_source_named_through_the_directory_above_is_the_file_it_names() {
        let entry = RawEntry {
            file: "../src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: Some(
                ["clang++", "-std=c++17", "../src/a.cpp"]
                    .map(str::to_string)
                    .to_vec(),
            ),
            command: None,
        }
        .entry()
        .expect("the entry carries a command");
        assert_eq!(entry.file, Path::new("/work/src/a.cpp"));
        // The unit's own source still says which unit this is rather than how
        // it is read, so it is still not one of the arguments.
        assert_eq!(
            entry.arguments,
            ["-working-directory=/work/build", "-std=c++17"]
        );
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
