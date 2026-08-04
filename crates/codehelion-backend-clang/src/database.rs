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
    /// The validated arguments to parse it with, or the reason the recorded
    /// invocation cannot safely be used by either compiler frontend.
    arguments: Result<ValidatedArguments, String>,
    /// The macros defined on the command line, as the flags spelled them.
    pub(crate) definitions: Vec<String>,
    /// The complete database identity used to select this entry.
    pub(crate) selector: CompileCommandSelector,
}

impl Entry {
    /// Arguments safe for both libclang and the helper-owned CFG frontend.
    ///
    /// Build commands can ask a compiler to load code, re-expand response
    /// files, or write an output. The CFG reader neither needs nor permits
    /// any of those. Refusing the entire auxiliary reading is deliberate: a
    /// command whose nested arguments are not known safe must not become safe
    /// by selectively guessing which pieces to retain.
    pub(crate) fn arguments(&self) -> Result<&ValidatedArguments, &str> {
        self.arguments.as_ref().map_err(String::as_str)
    }
}

/// Compiler arguments that the helper may give to either frontend.
///
/// Construction is private so an unchecked compilation-database argument
/// cannot accidentally reach libclang or the subprocess. The parser is an
/// allow list: an option added by a future compiler is unavailable until its
/// operand shape and read-only behaviour are reviewed here.
pub(crate) struct ValidatedArguments(Vec<String>);

impl ValidatedArguments {
    fn parse(arguments: &[String]) -> Result<Self, String> {
        let mut accepted = Vec::with_capacity(arguments.len());
        let mut index = 0;
        while index < arguments.len() {
            let argument = &arguments[index];
            if explicitly_forbidden(argument) {
                return Err(format!("compiler argument is not allowed: {argument}"));
            }
            if discard_without_value(argument) {
                index += 1;
                continue;
            }
            if SAFE_FLAGS.contains(&argument.as_str()) {
                accepted.push(argument.clone());
                index += 1;
                continue;
            }
            if let Some(value) = joined_short_value(argument) {
                require_nonempty(argument, value)?;
                accepted.push(argument.clone());
                index += 1;
                continue;
            }
            if let Some(value) = joined_long_value(argument) {
                require_nonempty(argument, value)?;
                accepted.push(argument.clone());
                index += 1;
                continue;
            }
            if SAFE_WITH_VALUE.contains(&argument.as_str()) {
                let Some(value) = arguments.get(index + 1) else {
                    return Err(format!("compiler argument requires a value: {argument}"));
                };
                if value.is_empty() {
                    return Err(format!("compiler argument has an empty value: {argument}"));
                }
                accepted.push(argument.clone());
                accepted.push(value.clone());
                index += 2;
                continue;
            }
            return Err(format!("compiler argument is not allowed: {argument}"));
        }
        Ok(Self(accepted))
    }

    /// The exact arguments whose option/value boundaries were validated.
    pub(crate) fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Whether every direct source-file read stays below `boundary`.
    ///
    /// Only options that make Clang open a named file are checked here. Include
    /// search paths remain available: they select headers as part of normal
    /// compilation, while `-include` and `-imacros` blindly open a caller
    /// supplied file before parsing the translation unit.
    pub(crate) fn reads_within(&self, boundary: &Path) -> bool {
        let boundary = canonical(boundary);
        let mut directory = boundary.clone();
        let mut index = 0;
        while index < self.0.len() {
            let argument = &self.0[index];
            let (option, value, consumed) = match argument.as_str() {
                "-include" | "-imacros" | "-working-directory" => {
                    let Some(value) = self.0.get(index + 1) else {
                        return false;
                    };
                    (argument.as_str(), value.as_str(), 2)
                }
                _ => {
                    if let Some(value) = argument.strip_prefix("-working-directory=") {
                        ("-working-directory", value, 1)
                    } else {
                        index += 1;
                        continue;
                    }
                }
            };
            let path = canonical(&resolve(Some(&directory), Path::new(value)));
            if !path.starts_with(&boundary) {
                return false;
            }
            if option == "-working-directory" {
                directory = path;
            }
            index += consumed;
        }
        true
    }
}

/// Read-only switches whose meaning does not consume another argument.
const SAFE_FLAGS: &[&str] = &[
    "-ansi",
    "-fblocks",
    "-fborland-extensions",
    "-fdeclspec",
    "-fdelayed-template-parsing",
    "-fexceptions",
    "-ffreestanding",
    "-fms-compatibility",
    "-fms-extensions",
    "-fno-blocks",
    "-fno-builtin",
    "-fno-exceptions",
    "-fno-rtti",
    "-fno-signed-char",
    "-fno-threadsafe-statics",
    "-fno-unsigned-char",
    "-fno-use-cxa-atexit",
    "-fno-wchar",
    "-fobjc-arc",
    "-fobjc-weak",
    "-fopenmp",
    "-frtti",
    "-fshort-enums",
    "-fshort-wchar",
    "-fsigned-char",
    "-fsyntax-only",
    "-fthreadsafe-statics",
    "-funsigned-char",
    "-fuse-cxa-atexit",
    "-fwchar",
    "-m32",
    "-m64",
    "-malign-double",
    "-mno-align-double",
    "-mno-red-zone",
    "-mred-zone",
    "-nobuiltininc",
    "-nostdinc",
    "-nostdinc++",
    "-nostdsysteminc",
    "-pthread",
    "-undef",
];

/// Read-only switches that consume their following argument.
const SAFE_WITH_VALUE: &[&str] = &[
    "--sysroot",
    "--target",
    "-D",
    "-F",
    "-I",
    "-U",
    "-arch",
    "-idirafter",
    "-iframework",
    "-iframeworkwithsysroot",
    "-imacros",
    "-include",
    "-iprefix",
    "-iquote",
    "-isystem",
    "-isysroot",
    "-iwithprefix",
    "-iwithprefixbefore",
    "-std",
    "-target",
    "-working-directory",
    "-x",
];

/// Short options for which Clang accepts the value in the same word.
fn joined_short_value(argument: &str) -> Option<&str> {
    ["-D", "-U", "-I", "-F"].into_iter().find_map(|option| {
        argument
            .strip_prefix(option)
            .filter(|value| !value.is_empty())
    })
}

/// Long options whose joined spelling has an explicit `=` boundary.
fn joined_long_value(argument: &str) -> Option<&str> {
    [
        "--sysroot=",
        "--target=",
        "-fclang-abi-compat=",
        "-fdebug-prefix-map=",
        "-ffile-prefix-map=",
        "-fmacro-prefix-map=",
        "-fms-compatibility-version=",
        "-fpack-struct=",
        "-fvisibility=",
        "-isysroot=",
        "-mabi=",
        "-march=",
        "-mcpu=",
        "-mfloat-abi=",
        "-mfpu=",
        "-mtune=",
        "-std=",
        "-stdlib=",
        "-target=",
        "-working-directory=",
        "-x=",
    ]
    .into_iter()
    .find_map(|option| argument.strip_prefix(option))
}

fn require_nonempty(argument: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("compiler argument has an empty value: {argument}"))
    } else {
        Ok(())
    }
}

/// Diagnostics and optimization controls that cannot affect the parsed
/// program and are intentionally not forwarded to either frontend.
fn discard_without_value(argument: &str) -> bool {
    argument == "-pedantic"
        || argument == "-pedantic-errors"
        || argument == "-Qunused-arguments"
        || matches!(
            argument,
            "-O" | "-O0"
                | "-O1"
                | "-O2"
                | "-O3"
                | "-O4"
                | "-Ofast"
                | "-Og"
                | "-Os"
                | "-Oz"
                | "-g"
                | "-g0"
                | "-g1"
                | "-g2"
                | "-g3"
                | "-ggdb"
                | "-ggdb0"
                | "-ggdb1"
                | "-ggdb2"
                | "-ggdb3"
                | "-gline-tables-only"
        )
        || argument.starts_with("-R")
        || argument.starts_with("-W")
}

/// Known command-line re-parsing and pass-through families are named here as
/// a defence-in-depth boundary before broad diagnostic namespaces are dropped.
/// Everything else still has to match the allow list and therefore fails
/// closed without relying on this list being exhaustive.
fn explicitly_forbidden(argument: &str) -> bool {
    argument.starts_with('@')
        || matches!(
            argument,
            "--config"
                | "--config-user-dir"
                | "--config-system-dir"
                | "-B"
                | "-Xanalyzer"
                | "-Xassembler"
                | "-Xclang"
                | "-Xlinker"
                | "-Xpreprocessor"
                | "-Wa"
                | "-Wl"
                | "-Wp"
                | "-add-plugin"
                | "-load"
                | "-mllvm"
                | "-plugin"
        )
        || [
            "--config=",
            "--config-user-dir=",
            "--config-system-dir=",
            "-B",
            "-Wa,",
            "-Wl,",
            "-Wp,",
            "-Xanalyzer=",
            "-Xassembler=",
            "-Xclang=",
            "-Xlinker=",
            "-Xpreprocessor=",
            "-fpass-plugin",
            "-fplugin",
        ]
        .into_iter()
        .any(|prefix| argument.starts_with(prefix))
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
            selector.is_none_or(|wanted| entry.selector.names_the_same_entry(wanted))
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
        let parsed_arguments = parse_arguments(&words, &written, directory.as_deref());
        let arguments = ValidatedArguments::parse(&parsed_arguments);
        Some(Entry {
            file: file.clone(),
            arguments,
            definitions: definitions(&words),
            selector: CompileCommandSelector {
                file: file.display().to_string(),
                directory: directory
                    .as_ref()
                    .map(|path| canonical(path).display().to_string()),
                arguments: words.clone(),
            },
        })
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
mod tests;
