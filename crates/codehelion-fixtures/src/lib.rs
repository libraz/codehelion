//! Where the analysis fixtures live, and what has to stay true of them.
//!
//! The fixtures under `fixtures/` are small projects whose right answer is
//! known by inspection, so that a compiler helper can be judged against
//! something other than its own output. They are not workspace members: an
//! ordinary build must not compile them, because two of them exist precisely so
//! a test can prove nobody ran their code.
//!
//! This crate is how the rest of the repository reaches them. It resolves paths
//! from its own manifest directory rather than from the working directory, so a
//! test finds the same fixture wherever it is run from, and it renders the
//! compilation databases that C and C++ helpers need.
//!
//! It also carries the fixtures' own tests. A fixture is a claim — "this crate
//! cannot be understood without running its build script", "this header means
//! two different things" — and a claim that quietly stops being true takes the
//! tests built on it with it, without any of them failing.
//!
//! Not every fixture can be a directory of files. A history is a fixture too,
//! and one made of commit ids cannot be committed as a tree; [`git`] plants it
//! instead, from a table, with everything a commit id depends on pinned.

pub mod git;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The Rust fixtures, by directory name under `fixtures/rust/`.
pub const RUST_FIXTURES: [&str; 7] = [
    "plain",
    "features",
    "dispatch",
    "macro-rules",
    "generic",
    "build-script",
    "proc-macro",
];

/// The C and C++ fixtures, by directory name under `fixtures/cpp/`.
pub const CPP_FIXTURES: [&str; 5] = [
    "cmake",
    "header-only",
    "macro-expansion",
    "overload-resolution",
    "template-instantiation",
];

/// The placeholder a committed compilation database carries where an absolute
/// path belongs.
///
/// A real `compile_commands.json` names the machine it was generated on, which
/// is why the committed document is a template and not the thing itself.
pub const DIRECTORY_PLACEHOLDER: &str = "@DIRECTORY@";

/// The name of the file a fixture's build script writes when it runs.
pub const EXECUTION_MARKER: &str = "build-script-ran.marker";

/// Something that went wrong reaching a fixture.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// The fixture directory is not where it should be.
    #[error("no fixture at {}", .0.display())]
    Missing(PathBuf),
    /// A path could not be written into a compilation database, which records
    /// paths as text.
    #[error("the path {} is not valid UTF-8", .0.display())]
    UnprintablePath(PathBuf),
    /// The compilation database did not parse.
    #[error("the compilation database at {path} did not parse: {source}")]
    Malformed {
        /// Which document.
        path: PathBuf,
        /// Why it did not parse.
        source: serde_json::Error,
    },
    /// The filesystem refused.
    #[error("{path}: {source}")]
    Io {
        /// What was being reached for.
        path: PathBuf,
        /// The underlying failure.
        source: std::io::Error,
    },
    /// The `git` binary could not be run at all.
    ///
    /// Separate from a command that ran and failed, because a missing tool is
    /// not a wrong answer, and a test that reports one as the other sends its
    /// reader looking for a bug that is not there.
    #[error("cannot run `{command}`: {source}")]
    GitUnavailable {
        /// The command that was attempted.
        command: String,
        /// Why it could not be started.
        source: std::io::Error,
    },
    /// A git command ran and refused.
    #[error("`{command}` failed{}: {stderr}", .status.map_or_else(String::new, |code| format!(" with status {code}")))]
    Git {
        /// The command that failed.
        command: String,
        /// Its exit status, when it had one.
        status: Option<i32>,
        /// What git wrote to its standard error.
        stderr: String,
    },
}

/// The `fixtures/` directory of this checkout.
#[must_use]
pub fn root() -> PathBuf {
    // Two levels up from `crates/codehelion-fixtures` is the repository root.
    // Resolved from the manifest rather than the working directory: a test run
    // by cargo starts in its own package, and one run by a person starts
    // anywhere.
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .unwrap_or(manifest)
        .join("fixtures")
}

/// The directory of a Rust fixture.
///
/// # Errors
///
/// Fails if no fixture of that name is present.
pub fn rust(name: &str) -> Result<PathBuf, FixtureError> {
    existing(root().join("rust").join(name))
}

/// Copies a Rust fixture into `destination` and returns the copied root.
///
/// The execution fixtures are copied before an opt-in test runs them: the
/// committed fixture is evidence that normal development never executed its
/// code, so a test must not spend that evidence in place.
///
/// # Errors
///
/// Fails if the fixture is absent or copying its files fails.
pub fn copy_rust(fixture: &str, destination: &Path) -> Result<PathBuf, FixtureError> {
    let source = rust(fixture)?;
    let root = destination.join(fixture);
    copy_tree(&source, &root)?;
    Ok(root)
}

/// The directory of a C or C++ fixture.
///
/// # Errors
///
/// Fails if no fixture of that name is present.
pub fn cpp(name: &str) -> Result<PathBuf, FixtureError> {
    existing(root().join("cpp").join(name))
}

fn existing(path: PathBuf) -> Result<PathBuf, FixtureError> {
    if path.is_dir() {
        Ok(path)
    } else {
        Err(FixtureError::Missing(path))
    }
}

/// Where a Rust fixture's build script would leave its mark.
///
/// The file is never expected to exist. It is what a test looks for to tell a
/// scan that declined to run the build script from one that ran it and ignored
/// the result — from the outside those produce the same findings, and only a
/// side effect distinguishes them.
///
/// # Errors
///
/// Fails if no fixture of that name is present.
pub fn execution_marker(fixture: &str) -> Result<PathBuf, FixtureError> {
    Ok(rust(fixture)?.join(EXECUTION_MARKER))
}

/// One entry of a compilation database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileCommand {
    /// The directory the compiler was invoked from.
    pub directory: String,
    /// The invocation, one argument per element.
    pub arguments: Vec<String>,
    /// The translation unit's main source file.
    pub file: String,
}

impl CompileCommand {
    /// The preprocessor definitions this invocation carries, without the `-D`.
    ///
    /// These are what make one translation unit's reading of a shared header
    /// differ from another's, so they are worth reaching for by name rather
    /// than by scanning the argument list at each use.
    #[must_use]
    pub fn defines(&self) -> Vec<&str> {
        self.arguments
            .iter()
            .filter_map(|argument| argument.strip_prefix("-D"))
            .filter(|define| !define.is_empty())
            .collect()
    }

    /// The include directories this invocation carries, without the `-I`.
    #[must_use]
    pub fn include_paths(&self) -> Vec<&str> {
        self.arguments
            .iter()
            .filter_map(|argument| argument.strip_prefix("-I"))
            .filter(|path| !path.is_empty())
            .collect()
    }
}

/// The compilation database a C or C++ fixture would have, with this
/// checkout's absolute path filled in.
///
/// # Errors
///
/// Fails if the fixture is absent, its template unreadable or malformed, or its
/// path not representable as text.
pub fn compile_commands(fixture: &str) -> Result<Vec<CompileCommand>, FixtureError> {
    let directory = cpp(fixture)?;
    let template = directory.join("compile_commands.json.in");
    let rendered = render(&template, &directory)?;
    serde_json::from_str(&rendered).map_err(|source| FixtureError::Malformed {
        path: template,
        source,
    })
}

/// Writes a fixture's compilation database into `destination` and returns the
/// path of the written document.
///
/// A helper is driven by a `compile_commands.json` on disk, so testing one
/// means producing a real document somewhere that is not the source tree.
///
/// # Errors
///
/// Fails if the fixture is absent, its template unreadable, or the destination
/// unwritable.
pub fn write_compile_commands(fixture: &str, destination: &Path) -> Result<PathBuf, FixtureError> {
    let directory = cpp(fixture)?;
    let rendered = compile_commands_for(&directory, &directory)?;
    let written = destination.join("compile_commands.json");
    std::fs::write(&written, rendered).map_err(|source| FixtureError::Io {
        path: written.clone(),
        source,
    })?;
    Ok(written)
}

/// Copies a C or C++ fixture into `destination`, database and all, and returns
/// the root of the copy.
///
/// A helper finds the database governing a file by walking up from that file,
/// so exercising one means a tree where the sources and the database naming
/// them are the same tree. The checkout cannot be it: rendering the database
/// there would leave a generated file, naming this machine, in the source tree.
/// So the fixture is copied and the database is rendered against the copy.
///
/// # Errors
///
/// Fails if the fixture is absent, its template unreadable, or the destination
/// unwritable.
pub fn copy_cpp(fixture: &str, destination: &Path) -> Result<PathBuf, FixtureError> {
    let source = cpp(fixture)?;
    let root = destination.join(fixture);
    copy_tree(&source, &root)?;
    let rendered = compile_commands_for(&source, &root)?;
    let written = root.join("compile_commands.json");
    std::fs::write(&written, rendered).map_err(|source| FixtureError::Io {
        path: written,
        source,
    })?;
    Ok(root)
}

/// One fixture's compilation database as a document, naming `root` as the
/// directory its commands run in.
///
/// Both writers render through here. A database written for a real compiler
/// has to be the same document whichever function wrote it: one that is
/// missing this machine's arguments drives a compiler that resolves the
/// standard library to nothing, and a test then reads that silence as an
/// answer about the fixture.
fn compile_commands_for(fixture: &Path, root: &Path) -> Result<String, FixtureError> {
    let template = fixture.join("compile_commands.json.in");
    let mut entries: Vec<CompileCommand> = serde_json::from_str(&render(&template, root)?)
        .map_err(|source| FixtureError::Malformed {
            path: template.clone(),
            source,
        })?;
    for entry in &mut entries {
        entry.arguments.splice(1..1, platform_arguments());
    }
    serde_json::to_string_pretty(&entries).map_err(|source| FixtureError::Malformed {
        path: template,
        source,
    })
}

/// What a database generated on this machine would carry that a committed
/// template cannot.
///
/// On macOS the standard library lives inside an SDK whose path names the
/// developer tools installed here, and a compiler invoked without it finds no
/// `<vector>` at all — the parse succeeds, every standard type resolves to
/// nothing, and a test reads the silence as an answer. A generator run on this
/// machine writes the path into every entry it emits, which is the same reason
/// the committed fixture is a template: a real compilation database names the
/// machine it was made on.
///
/// `SDKROOT` first, because that is what a developer who has moved their tools
/// sets; then the two places the tools install. Empty everywhere else, where
/// the compiler finds its own standard library.
fn platform_arguments() -> Vec<String> {
    /// Where the developer tools put an SDK, in the order they are tried.
    const SDKS: [&str; 2] = [
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
        "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
    ];
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    let configured = std::env::var_os("SDKROOT").map(PathBuf::from);
    let sdk = configured
        .into_iter()
        .chain(SDKS.iter().map(PathBuf::from))
        .find(|path| path.is_dir());
    sdk.and_then(|path| path.to_str().map(str::to_string))
        .map(|path| vec!["-isysroot".to_string(), path])
        .unwrap_or_default()
}

fn copy_tree(from: &Path, to: &Path) -> Result<(), FixtureError> {
    std::fs::create_dir_all(to).map_err(|source| FixtureError::Io {
        path: to.to_path_buf(),
        source,
    })?;
    let entries = std::fs::read_dir(from).map_err(|source| FixtureError::Io {
        path: from.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| FixtureError::Io {
            path: from.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let target = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &target)?;
        } else {
            std::fs::copy(&path, &target).map_err(|source| FixtureError::Io {
                path: path.clone(),
                source,
            })?;
        }
    }
    Ok(())
}

fn render(template: &Path, directory: &Path) -> Result<String, FixtureError> {
    let text = std::fs::read_to_string(template).map_err(|source| FixtureError::Io {
        path: template.to_path_buf(),
        source,
    })?;
    let printable = directory
        .to_str()
        .ok_or_else(|| FixtureError::UnprintablePath(directory.to_path_buf()))?;
    // The placeholder stands inside a JSON string, and a path is not made
    // only of characters JSON leaves alone — on Windows every separator is a
    // backslash, which reads as the start of an escape. Written the way JSON
    // says to write it, so the rendered database is still a database.
    let quoted = serde_json::to_string(printable).map_err(|source| FixtureError::Malformed {
        path: template.to_path_buf(),
        source,
    })?;
    let escaped = quoted
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
        .unwrap_or(quoted.as_str());
    Ok(text.replace(DIRECTORY_PLACEHOLDER, escaped))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// Where the checkout sits is not this repository's to choose, and on one
    /// of the platforms it runs on every separator in that path is a
    /// character JSON reserves.
    #[test]
    fn a_directory_json_would_read_as_escapes_still_renders_a_database() {
        let scratch = tempfile::tempdir().unwrap();
        let template = scratch.path().join("compile_commands.json.in");
        std::fs::write(
            &template,
            format!("[{{\"directory\": \"{DIRECTORY_PLACEHOLDER}\"}}]"),
        )
        .unwrap();
        let awkward = Path::new(r#"C:\a\codehelion\"quoted""#);

        let rendered = render(&template, awkward).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|error| panic!("{rendered} is not a database: {error}"));
        assert_eq!(parsed[0]["directory"], awkward.to_str().unwrap());
    }

    /// Both of the databases this crate writes are there to drive a real
    /// compiler, so which function wrote one cannot change the arguments it
    /// carries. Only the root the commands are anchored at is allowed to
    /// differ, and that is what the two are compared modulo.
    #[test]
    fn both_written_databases_give_a_fixture_the_same_arguments() {
        let scratch = tempfile::tempdir().unwrap();
        let fixture = "header-only";
        let written = write_compile_commands(fixture, scratch.path()).unwrap();
        let copied = copy_cpp(fixture, scratch.path()).unwrap();
        let anchored = |database: &Path, root: &Path| -> Vec<Vec<String>> {
            serde_json::from_str::<Vec<CompileCommand>>(&read(database))
                .unwrap()
                .into_iter()
                .map(|entry| {
                    entry
                        .arguments
                        .iter()
                        .map(|argument| {
                            argument.replace(root.to_str().unwrap(), DIRECTORY_PLACEHOLDER)
                        })
                        .collect()
                })
                .collect()
        };

        assert_eq!(
            anchored(&written, &cpp(fixture).unwrap()),
            anchored(&copied.join("compile_commands.json"), &copied)
        );
        let platform = platform_arguments();
        assert!(
            anchored(&written, &cpp(fixture).unwrap())
                .iter()
                .all(|arguments| arguments[1..=platform.len()] == platform[..]),
            "the arguments this machine adds are missing or misplaced"
        );
    }

    /// A renamed or deleted fixture would otherwise be discovered one test at a
    /// time, by whichever helper happened to reach for it first.
    #[test]
    fn every_named_fixture_is_where_it_says_it_is() {
        for name in RUST_FIXTURES {
            let path = rust(name).unwrap();
            assert!(path.join("Cargo.toml").is_file(), "{}", path.display());
        }
        for name in CPP_FIXTURES {
            let path = cpp(name).unwrap();
            assert!(
                path.join("compile_commands.json.in").is_file(),
                "{}",
                path.display()
            );
        }
    }

    /// The fixtures that exist to be *not* executed have to have something to
    /// execute. A test proving a build script did not run against a crate with
    /// no build script proves nothing, and would go on passing after the build
    /// script was deleted.
    #[test]
    fn the_fixtures_that_can_execute_code_still_can() {
        assert!(
            rust("build-script").unwrap().join("build.rs").is_file(),
            "the build-script fixture has no build script left to decline to run"
        );
        let manifest = read(
            &rust("proc-macro")
                .unwrap()
                .join("labelled-derive/Cargo.toml"),
        );
        assert!(
            manifest.contains("proc-macro = true"),
            "the proc-macro fixture no longer declares a procedural macro"
        );
    }

    /// And the plain ones have to have nothing, or they are not a control: a
    /// difference between them and the executing fixtures is only evidence if
    /// execution is the difference.
    #[test]
    fn the_baseline_fixtures_have_nothing_to_execute() {
        // `macro-rules` belongs here too: a declarative macro is expanded by
        // reading it, so a fixture full of them still has nothing to run.
        for name in ["plain", "features", "dispatch", "macro-rules", "generic"] {
            let path = rust(name).unwrap();
            assert!(
                !path.join("build.rs").is_file(),
                "{name} has grown a build script"
            );
            for manifest in ["Cargo.toml", "ledger/Cargo.toml", "report/Cargo.toml"] {
                let manifest = path.join(manifest);
                if manifest.is_file() {
                    assert!(
                        !read(&manifest).contains("proc-macro"),
                        "{} has grown a procedural macro",
                        manifest.display()
                    );
                }
            }
        }
    }

    /// The standing check. If an ordinary build or test run ever compiles the
    /// build-script fixture, this is where it shows up — and it shows up in
    /// every checkout, not only in the one test that cared.
    #[test]
    fn no_fixture_build_script_has_run_in_this_checkout() {
        let marker = execution_marker("build-script").unwrap();
        assert!(
            !marker.exists(),
            "{} exists: something built the fixture that is only ever supposed to be read",
            marker.display()
        );
    }

    /// The committed document must not name the machine it was written on, and
    /// must be a document rather than nearly one — a template that only becomes
    /// valid JSON after substitution hides its own syntax errors until use.
    #[test]
    fn the_committed_database_is_a_document_that_names_no_machine() {
        for name in CPP_FIXTURES {
            let template = cpp(name).unwrap().join("compile_commands.json.in");
            let text = read(&template);
            let entries: Vec<CompileCommand> = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", template.display()));
            assert!(!entries.is_empty(), "{name} has an empty database");
            for entry in entries {
                assert_eq!(
                    entry.directory, DIRECTORY_PLACEHOLDER,
                    "{name} records a real directory rather than the placeholder"
                );
            }
        }
    }

    /// Rendering has to produce paths that are actually there. A source file
    /// renamed without its database entry leaves a document that parses,
    /// resolves, and describes a compilation nobody can perform.
    #[test]
    fn a_rendered_database_points_at_files_that_exist() {
        for name in CPP_FIXTURES {
            for entry in compile_commands(name).unwrap() {
                assert!(
                    Path::new(&entry.file).is_file(),
                    "{name} names a missing source: {}",
                    entry.file
                );
                assert!(Path::new(&entry.directory).is_dir(), "{name}");
                for include in entry.include_paths() {
                    assert!(
                        Path::new(include).is_dir(),
                        "{name} names a missing include directory: {include}"
                    );
                }
            }
        }
    }

    /// The whole point of the header-only fixture: one header, two translation
    /// units, and a define that differs between them. If the two invocations
    /// ever agree, the fixture stops posing the question it exists to pose.
    #[test]
    fn the_shared_header_is_compiled_two_different_ways() {
        let entries = compile_commands("header-only").unwrap();
        assert_eq!(entries.len(), 2);
        let widths: Vec<Vec<&str>> = entries.iter().map(CompileCommand::defines).collect();
        assert_ne!(widths[0], widths[1], "both translation units agree");
        assert!(
            widths
                .iter()
                .any(|defines| defines.contains(&"ACCUM_WIDTH=64")),
            "neither translation unit widens the accumulator: {widths:?}"
        );

        let header = cpp("header-only").unwrap().join("include/accumulate.hpp");
        for entry in &entries {
            let source = read(Path::new(&entry.file));
            assert!(
                source.contains("accumulate.hpp"),
                "{} does not include the shared header",
                entry.file
            );
        }
        assert!(header.is_file());
    }

    /// What the macro-expansion fixture poses: one macro body, invoked more
    /// than once, and a declaration beside them that came from nowhere else. A
    /// fixture with one invocation would go on passing every test built on it
    /// while proving nothing about repetition, and one whose file held only
    /// expansions could not tell "everything here was written once" apart from
    /// "the answer is the same for everything".
    #[test]
    fn one_macro_body_is_stamped_out_more_than_once() {
        let root = cpp("macro-expansion").unwrap();
        let header = read(&root.join("include/accessor.hpp"));
        assert!(
            header.contains("#define ACCESSOR("),
            "the fixture no longer defines the macro it exists for"
        );
        assert!(
            header.matches("ACCESSOR(std::uint32_t,").count() >= 2,
            "one invocation is not repetition"
        );
        assert!(
            read(&root.join("src/frame.cpp")).contains("std::uint32_t volume("),
            "nothing in the fixture is written where it reads any more"
        );
    }

    /// The template fixture keeps every distinction the helper has to report:
    /// repeated and differently substituted function uses, class type and
    /// non-type arguments, a selected partial specialization, and controls that
    /// must not be attributed to the primary template body.
    #[test]
    fn template_uses_cover_specialization_and_control_cases() {
        let root = cpp("template-instantiation").unwrap();
        let header = read(&root.join("include/templates.hpp"));
        let source = read(&root.join("src/templates.cpp"));
        assert_eq!(
            source.matches("twice(").count(),
            3,
            "the fixture no longer distinguishes repetition from substitution"
        );
        for use_ in ["Buffer<int, 4>", "Buffer<int, 8>", "Buffer<double, 4>"] {
            assert!(source.contains(use_), "missing class use {use_}");
        }
        assert!(
            header.contains("Buffer<int, 16> shared_buffer"),
            "the header no longer has a template use read by both units"
        );
        assert!(
            header.contains("struct Holder<T*>"),
            "the selected partial specialization is gone"
        );
        assert!(
            header.contains("struct Holder<bool>"),
            "the explicit full-specialization control is gone"
        );
        assert!(
            source.contains("std::vector<int>") && source.contains("ordinary("),
            "the external or non-template control is gone"
        );
    }

    /// The overload fixture separates compile-time overload selection from
    /// calls whose runtime target libclang cannot completely enumerate.
    #[test]
    fn overload_calls_cover_static_and_unresolved_targets() {
        let root = cpp("overload-resolution").unwrap();
        let header = read(&root.join("include/calls.hpp"));
        let source = read(&root.join("src/calls.cpp"));
        for declaration in [
            "int choose(int value)",
            "long choose(long value)",
            "virtual int run(int value) const",
            "int run(int value) const override",
        ] {
            assert!(header.contains(declaration), "missing {declaration}");
        }
        for call in [
            "choose(1)",
            "choose(1L)",
            "mixer.mix(2)",
            "mixer.mix(2L)",
            "base.run(3)",
            "derived.Base::run(4)",
            "pointer(6)",
            "CALL_DIRECT(7)",
            "std::puts",
        ] {
            assert!(source.contains(call), "missing {call}");
        }
        assert!(
            header.contains("return choose(value);"),
            "the dependent call is gone"
        );
        assert!(
            header.contains("HEADER_ARGUMENT"),
            "the shared header call no longer varies by translation unit"
        );
    }

    #[test]
    fn a_written_database_is_a_real_document_somewhere_else() {
        let destination = tempfile::tempdir().unwrap();
        let written = write_compile_commands("cmake", destination.path()).unwrap();
        assert_eq!(written.file_name().unwrap(), "compile_commands.json");
        let entries: Vec<CompileCommand> = serde_json::from_str(&read(&written)).unwrap();
        // The fixture's own database, filled in for this machine: what a
        // compiler is driven with here is the template plus whatever this
        // installation needs to find its standard library.
        let mut expected = compile_commands("cmake").unwrap();
        for entry in &mut expected {
            entry.arguments.splice(1..1, platform_arguments());
        }
        assert_eq!(entries, expected);
        assert!(!read(&written).contains(DIRECTORY_PLACEHOLDER));
    }

    #[test]
    fn a_fixture_that_is_not_there_is_an_error_rather_than_a_path() {
        let error = rust("no-such-fixture").unwrap_err();
        assert!(matches!(error, FixtureError::Missing(_)), "{error:?}");
    }
}
