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
            entry
                .arguments()
                .expect("ordinary compilation arguments are safe")
                .as_slice(),
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
    fn compiler_arguments_fail_closed_for_execution_and_output_options() {
        let rejected: &[&[&str]] = &[
            &["--config", "evil.cfg"],
            &["--config=evil.cfg"],
            &["--config-user-dir", "/tmp/config"],
            &["--config-user-dir=/tmp/config"],
            &["--config-system-dir", "/tmp/config"],
            &["--config-system-dir=/tmp/config"],
            &["-B", "/tmp/toolchain"],
            &["-B/tmp/toolchain"],
            &["@evil.rsp"],
            &["-Xclang", "-load"],
            &["-load", "/tmp/plugin.so"],
            &["-plugin", "example"],
            &["-add-plugin", "example"],
            &["-fplugin=/tmp/plugin.so"],
            &["-fplugin-arg-example=value"],
            &["-fpass-plugin=/tmp/pass.so"],
            &["-fmodules"],
            &["-fmodule-file=/tmp/module.pcm"],
            &["-fmodule-map-file=/tmp/module.modulemap"],
            &["-fimplicit-modules"],
            &["-include-pch", "/tmp/header.pch"],
            &["-emit-pch"],
            &["-emit-module"],
            &["-ast-merge", "/tmp/unit.ast"],
            &["-emit-ast"],
            &["-o", "/tmp/output"],
            &["-save-temps"],
            &["-serialize-diagnostics", "/tmp/diagnostics.dia"],
            &["-ftime-trace"],
            &["-MJ", "/tmp/fragment.json"],
            &["-analyzer-checker=example"],
            &["-Xanalyzer", "-analyzer-output=text"],
            &["-mllvm", "-example"],
            &["-Xpreprocessor", "-example"],
            &["-Wp,-example"],
            &["-Xlinker", "-example"],
            &["-Wl,-example"],
            &["-Xassembler", "-example"],
            &["-Wa,-example"],
            &["--future-unknown-option"],
            &["positional-operand.cpp"],
        ];
        for arguments in rejected {
            let arguments: Vec<String> = arguments.iter().map(ToString::to_string).collect();
            assert!(
                ValidatedArguments::parse(&arguments).is_err(),
                "unexpectedly accepted {arguments:?}"
            );
        }
    }

    #[test]
    fn allow_list_retains_joined_and_separate_semantic_inputs() {
        let arguments = [
            "-working-directory=/work/build",
            "-working-directory",
            "/work/other-build",
            "-std=c++20",
            "-std",
            "c++23",
            "-DLEVEL=2",
            "-D",
            "FEATURE=1",
            "-UOLD",
            "-U",
            "OLDER",
            "-I/work/include",
            "-I",
            "/work/generated",
            "-isystem",
            "/opt/sdk/include",
            "-include",
            "/work/prefix.hpp",
            "--target=x86_64-unknown-linux-gnu",
            "-target",
            "aarch64-apple-darwin",
            "-m64",
            "-mabi=lp64",
        ]
        .map(str::to_string)
        .to_vec();
        assert_eq!(
            ValidatedArguments::parse(&arguments)
                .expect("ordinary parsing flags are safe")
                .as_slice(),
            arguments
        );
    }

    #[test]
    fn option_operands_are_consumed_once_and_missing_operands_are_rejected() {
        let arguments = ["-I", "-Xclang", "-D", "-load", "-include", "-plugin"]
            .map(str::to_string)
            .to_vec();
        assert_eq!(
            ValidatedArguments::parse(&arguments)
                .expect("option-looking paths and macro names are still operands")
                .as_slice(),
            arguments
        );
        for option in SAFE_WITH_VALUE {
            assert!(
                ValidatedArguments::parse(&[(*option).to_string()]).is_err(),
                "accepted {option} without its operand"
            );
        }
    }

    #[test]
    fn both_compilation_database_command_forms_reach_the_same_allow_list() {
        let from_arguments = RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: Some(
                [
                    "clang++",
                    "-D",
                    "LEVEL=2",
                    "-UOLD",
                    "-I",
                    "../include",
                    "-isystem",
                    "/opt/sdk/include",
                    "-include",
                    "prefix.hpp",
                    "-std",
                    "c++20",
                    "--target=x86_64-unknown-linux-gnu",
                    "/work/src/a.cpp",
                ]
                .map(str::to_string)
                .to_vec(),
            ),
            command: None,
        }
        .entry()
        .expect("arguments entry");
        assert!(from_arguments.arguments().is_ok());

        let from_command = RawEntry {
            file: "/work/src/a.cpp".to_string(),
            directory: Some("/work/build".to_string()),
            arguments: None,
            command: Some(
                "clang++ -DLEVEL=2 -U OLD -I../include -isystem /opt/sdk/include \
                 -include prefix.hpp -std=c++20 -target x86_64-unknown-linux-gnu \
                 /work/src/a.cpp"
                    .to_string(),
            ),
        }
        .entry()
        .expect("command entry");
        assert!(from_command.arguments().is_ok());

        for unsafe_entry in [
            RawEntry {
                file: "/work/src/a.cpp".to_string(),
                directory: Some("/work/build".to_string()),
                arguments: Some(
                    ["clang++", "--config=evil.cfg", "/work/src/a.cpp"]
                        .map(str::to_string)
                        .to_vec(),
                ),
                command: None,
            },
            RawEntry {
                file: "/work/src/a.cpp".to_string(),
                directory: Some("/work/build".to_string()),
                arguments: None,
                command: Some("clang++ @evil.rsp /work/src/a.cpp".to_string()),
            },
        ] {
            assert!(
                unsafe_entry
                    .entry()
                    .expect("entry is retained so analysis can report unavailable")
                    .arguments()
                    .is_err()
            );
        }
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
            entry
                .arguments()
                .expect("include path is safe")
                .as_slice()
                .first()
                .map(String::as_str),
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
            entry
                .arguments()
                .expect("standard selection is safe")
                .as_slice(),
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
