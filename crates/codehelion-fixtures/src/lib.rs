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
pub const CPP_FIXTURES: [&str; 2] = ["cmake", "header-only"];

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
    let rendered = render(&directory.join("compile_commands.json.in"), &directory)?;
    let written = destination.join("compile_commands.json");
    std::fs::write(&written, rendered).map_err(|source| FixtureError::Io {
        path: written.clone(),
        source,
    })?;
    Ok(written)
}

fn render(template: &Path, directory: &Path) -> Result<String, FixtureError> {
    let text = std::fs::read_to_string(template).map_err(|source| FixtureError::Io {
        path: template.to_path_buf(),
        source,
    })?;
    let printable = directory
        .to_str()
        .ok_or_else(|| FixtureError::UnprintablePath(directory.to_path_buf()))?;
    Ok(text.replace(DIRECTORY_PLACEHOLDER, printable))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
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

    #[test]
    fn a_written_database_is_a_real_document_somewhere_else() {
        let destination = tempfile::tempdir().unwrap();
        let written = write_compile_commands("cmake", destination.path()).unwrap();
        assert_eq!(written.file_name().unwrap(), "compile_commands.json");
        let entries: Vec<CompileCommand> = serde_json::from_str(&read(&written)).unwrap();
        assert_eq!(entries, compile_commands("cmake").unwrap());
        assert!(!read(&written).contains(DIRECTORY_PLACEHOLDER));
    }

    #[test]
    fn a_fixture_that_is_not_there_is_an_error_rather_than_a_path() {
        let error = rust("no-such-fixture").unwrap_err();
        assert!(matches!(error, FixtureError::Missing(_)), "{error:?}");
    }
}
