//! Reading, without loading anything, what a tree asks to have run.
//!
//! Whether a package declares a build script and whether a workspace's Cargo
//! configuration names a program for Cargo to start are the two judgements the
//! execution policy turns on, so they are read here — line by line, from files
//! that need not be well-formed enough to load — rather than left to whatever a
//! loader happens to do with them. The manifest walks that find those files
//! live beside them, because where the walk stops is part of the same answer.

use std::path::{Path, PathBuf};

use crate::boundary::ReadBoundary;

/// Whether an answer may be built from `path`.
///
/// True for every path when no boundary was set, which is what a trusted scan
/// asks for: the project decides where its own manifests are.
pub(super) fn within(path: &Path, boundary: Option<&ReadBoundary>) -> bool {
    boundary.is_none_or(|boundary| boundary.holds(path))
}

/// The `Cargo.toml` governing `path`, found by walking up from it.
///
/// The walk stops at `boundary` rather than climbing past it and being refused
/// afterwards. The two decline the same requests; only this one leaves the
/// directories above a boundary unread.
pub(super) fn nearest_manifest(path: &Path, boundary: Option<&ReadBoundary>) -> Option<PathBuf> {
    let start = if path.is_dir() { path } else { path.parent()? };
    start
        .ancestors()
        .take_while(|directory| within(directory, boundary))
        .find_map(|directory| {
            let manifest = directory.join("Cargo.toml");
            manifest.is_file().then_some(manifest)
        })
}

/// The manifest of the workspace `manifest` belongs to, or `manifest` itself
/// when it is not a member of one.
///
/// The *nearest* enclosing declaration wins, and the search stops there. Taking
/// the outermost instead would attach a project to whatever workspace happens
/// to sit above it on this machine — a checkout under another repository would
/// be read as part of it.
///
/// Not bounded, because this is the search whose result decides whether a
/// request under a boundary can be answered at all: Cargo performs the same
/// walk when it loads a member, so a workspace above the boundary is one the
/// caller has to be told about rather than one that can be pretended away.
pub(super) fn workspace_manifest(manifest: &Path) -> PathBuf {
    manifest
        .parent()
        .into_iter()
        .flat_map(Path::ancestors)
        .map(|directory| directory.join("Cargo.toml"))
        .find(|candidate| candidate.is_file() && declares_workspace(candidate))
        .unwrap_or_else(|| manifest.to_path_buf())
}

fn declares_workspace(manifest: &Path) -> bool {
    std::fs::read_to_string(manifest)
        .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
}

/// Whether the package at `manifest` builds something before it compiles.
///
/// The claim being made is "this crate has a build script and nothing ran it",
/// and the package's own manifest is what settles it: a `build` key names the
/// script, or turns off the `build.rs` beside the manifest that would otherwise
/// be one. How much of the crate depends on what that script would have
/// produced is not knowable without running it, which is the thing being
/// declined.
///
/// Both halves of getting it wrong cost something. A script missed here is a
/// crate analysed against types that were never generated, reported as a
/// complete reading; a script imagined here is a crate refused for needing a
/// permission that would buy nothing.
pub(super) fn has_build_script(manifest: &Path) -> bool {
    let declared = std::fs::read_to_string(manifest)
        .map_or(Declared::Unsaid, |text| declared_build_script(&text));
    match declared {
        Declared::Script => true,
        Declared::None => false,
        Declared::Unsaid => manifest.with_file_name("build.rs").is_file(),
    }
}

/// What a manifest's own `[package]` table says about a build script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Declared {
    /// A script: named, or a list of names, or the default file asked for.
    Script,
    /// None, whatever sits beside the manifest.
    None,
    /// Nothing, so the file beside the manifest is the whole of the answer.
    Unsaid,
}

/// What `manifest` declares about its build script.
///
/// Read line by line rather than parsed, because the question is small and the
/// answer must not depend on a manifest being well-formed enough to load. What
/// the reading does have to survive is how TOML lets the same declaration be
/// spelled — either quoting style, spaces around the `=` or none — and which
/// table a key sits in: a `build` under `[package.metadata]` belongs to
/// whatever reads that table, and is not this package declaring a script.
fn declared_build_script(manifest: &str) -> Declared {
    let mut table = "";
    for line in manifest.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            table = header
                .split(']')
                .next()
                .unwrap_or_default()
                .trim_start_matches('[')
                .trim();
            continue;
        }
        if table != "package" {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !names_the_build_key(key.trim()) {
            continue;
        }
        return declared_by(value.trim());
    }
    Declared::Unsaid
}

/// Whether `key` is the `build` key itself.
///
/// Quoted or bare, which TOML treats as one key. Nothing else counts: a line of
/// an array elsewhere in the table can begin with the letters of a key and an
/// `=`, and only the closing quote tells the two apart.
fn names_the_build_key(key: &str) -> bool {
    matches!(key, "build" | "\"build\"" | "'build'")
}

/// What a `build` key set to `value` says.
fn declared_by(value: &str) -> Declared {
    if value.starts_with('"') || value.starts_with('\'') || value.starts_with('[') {
        // A script path, or a list of them.
        return Declared::Script;
    }
    if value.starts_with("false") {
        return Declared::None;
    }
    if value.starts_with("true") {
        // The default file, which is the one beside the manifest.
        return Declared::Unsaid;
    }
    // A spelling this does not know. Read as a declaration rather than as
    // silence: the key is there, and a crate refused for a script it may not
    // have costs a permission prompt, where one analysed without a script it
    // does have costs a wrong answer that looks right.
    Declared::Script
}

/// A program the tree under analysis asked Cargo to run.
pub(super) struct NamedProgram {
    /// The file that names it, which is a file in the tree.
    pub(super) file: PathBuf,
    /// The key that names it, spelled as a person would look it up.
    pub(super) key: String,
}

/// The Cargo configuration files a directory can carry, in the order Cargo
/// prefers them. Both are read here: the second is the older spelling, and a
/// tree that uses it is read by Cargo the same way.
const CARGO_CONFIGURATION_FILES: [&str; 2] = ["config.toml", "config"];

/// What the workspace at `root` asks Cargo to run, if it asks for anything.
///
/// Its own directory and no other. Cargo finds configuration by walking up from
/// where it was started, and where it is started for this workspace is here, so
/// the files above this directory belong to the machine rather than to the tree
/// and a `.cargo` inside a member is one Cargo never reads.
pub(super) fn program_named_by(root: &Path) -> Option<NamedProgram> {
    let directory = root.join(".cargo");
    CARGO_CONFIGURATION_FILES.iter().find_map(|name| {
        let file = directory.join(name);
        let key = program_naming_key(&std::fs::read_to_string(&file).ok()?)?;
        Some(NamedProgram { file, key })
    })
}

/// The first key in `configuration` that names a program for Cargo to run.
///
/// Read key by key rather than parsed, for the reason a manifest is: what is
/// being looked for is small, and a file too malformed for Cargo to load is not
/// a file this may decide names nothing. Tables and keys may be quoted, and a
/// table may be written inline, so all three spellings of one key reach the
/// same answer.
fn program_naming_key(configuration: &str) -> Option<String> {
    let mut table: Vec<String> = Vec::new();
    for line in configuration.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if let Some(header) = line.strip_prefix('[') {
            table = key_path(
                header
                    .split(']')
                    .next()
                    .unwrap_or_default()
                    .trim_start_matches('['),
            );
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let mut path = table.clone();
        path.extend(key_path(key));
        if names_a_program(&path) {
            return Some(path.join("."));
        }
        // An inline table writes the rest of the path on the same line.
        for nested in inline_keys(value) {
            let mut path = path.clone();
            path.push(nested);
            if names_a_program(&path) {
                return Some(path.join("."));
            }
        }
    }
    None
}

/// A dotted key, split into the segments Cargo looks it up by.
///
/// Quotes come off and a dot inside them is part of a segment rather than a
/// separator, which is how a target key names the settings it applies to.
fn key_path(key: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut segment = String::new();
    let mut quote = None;
    for character in key.chars() {
        match character {
            '"' | '\'' if quote == Some(character) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(character),
            '.' if quote.is_none() => segments.push(std::mem::take(&mut segment)),
            _ => segment.push(character),
        }
    }
    segments.push(segment);
    segments
        .into_iter()
        .map(|segment| segment.trim().to_owned())
        .collect()
}

/// The keys written inside an inline table, at whatever depth they sit.
///
/// The depth is dropped on purpose: what a key is looked up under is decided by
/// the table it opens and the name it ends with, and both survive.
fn inline_keys(value: &str) -> Vec<String> {
    if !value.contains('{') {
        return Vec::new();
    }
    value
        .split(['{', '}', ','])
        .filter_map(|part| part.split_once('='))
        .flat_map(|(key, _)| key_path(key))
        .filter(|key| !key.is_empty())
        .collect()
}

/// Whether a Cargo configuration key names a program to start.
///
/// Matched by the table a key opens and the name it ends with, because the
/// settings between the two are a target expression a tree chooses. Every key
/// here hands Cargo a command line: a compiler, a program to run around it, a
/// linker, a runner for what was built, a credential helper, or the request to
/// fetch through the installed `git`.
fn names_a_program(path: &[String]) -> bool {
    let (Some(table), Some(key)) = (path.first(), path.last()) else {
        return false;
    };
    match (table.as_str(), key.as_str()) {
        ("build", "rustc" | "rustc-wrapper" | "rustc-workspace-wrapper" | "rustdoc")
        | ("target" | "host", "linker" | "runner")
        | ("registry" | "registries", "credential-provider")
        | ("net", "git-fetch-with-cli") => true,
        ("credential-alias", _) => path.len() > 1,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{Declared, declared_build_script, has_build_script, program_naming_key};

    fn package(body: &str) -> String {
        format!("[package]\nname = \"p\"\nversion = \"0.1.0\"\n{body}")
    }

    #[test]
    fn a_named_build_script_is_declared_however_it_is_quoted() {
        assert_eq!(
            declared_build_script(&package("build = \"b.rs\"\n")),
            Declared::Script
        );
        assert_eq!(
            declared_build_script(&package("build='custom.rs'\n")),
            Declared::Script
        );
        assert_eq!(
            declared_build_script(&package("  build   =   \"b.rs\"  # named\n")),
            Declared::Script
        );
        assert_eq!(
            declared_build_script(&package("build = [\"first.rs\", \"second.rs\"]\n")),
            Declared::Script
        );
    }

    #[test]
    fn a_build_key_set_to_false_declares_no_build_script() {
        assert_eq!(
            declared_build_script(&package("build = false\n")),
            Declared::None
        );
        assert_eq!(
            declared_build_script(&package("build=false\n")),
            Declared::None
        );
    }

    /// `true` asks for the default file rather than naming one, so what is
    /// beside the manifest is still what decides.
    #[test]
    fn a_build_key_set_to_true_leaves_the_file_beside_the_manifest_to_decide() {
        assert_eq!(
            declared_build_script(&package("build = true\n")),
            Declared::Unsaid
        );
    }

    /// The key belongs to `[package]`. Another table's `build` is that table's
    /// own word, and a package refused over it would be refused for something
    /// it never said.
    #[test]
    fn a_build_key_in_another_table_is_not_this_packages_declaration() {
        assert_eq!(
            declared_build_script(&package(
                "\n[package.metadata.release]\nbuild = \"cross\"\n"
            )),
            Declared::Unsaid
        );
        assert_eq!(
            declared_build_script(&package("\n[dependencies]\nbuild = \"1\"\n")),
            Declared::Unsaid
        );
    }

    /// A value elsewhere in `[package]` can hold the letters of the key and an
    /// `=`, and does not make the package declare anything.
    #[test]
    fn a_string_that_reads_like_the_build_key_is_not_the_build_key() {
        assert_eq!(
            declared_build_script(&package(
                "keywords = [\n  \"build = false\",\n]\ndescription = \"build = false\"\n"
            )),
            Declared::Unsaid
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // Test setup requires a writable temporary directory.
    fn a_declaration_of_none_outranks_the_file_beside_the_manifest() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let manifest = directory.path().join("Cargo.toml");
        std::fs::write(directory.path().join("build.rs"), "fn main() {}\n")
            .expect("writing a build script");

        std::fs::write(&manifest, package("")).expect("writing a manifest");
        assert!(
            has_build_script(&manifest),
            "a build.rs beside an unsaying manifest is a build script"
        );

        std::fs::write(&manifest, package("build = false\n")).expect("writing a manifest");
        assert!(
            !has_build_script(&manifest),
            "the package turned the file beside it off"
        );

        std::fs::remove_file(directory.path().join("build.rs")).expect("removing the script");
        std::fs::write(&manifest, package("build = \"b.rs\"\n")).expect("writing a manifest");
        assert!(
            has_build_script(&manifest),
            "a named script is declared whether or not it is the default name"
        );

        std::fs::write(&manifest, package("")).expect("writing a manifest");
        assert!(
            !has_build_script(&manifest),
            "nothing said and nothing beside it is no build script"
        );
    }

    #[test]
    fn a_configuration_that_names_a_program_is_found_however_it_is_written() {
        for configuration in [
            "[build]\nrustc-wrapper = \"/tmp/anything\"\n",
            "[build]\nrustc = '/tmp/anything'\n",
            "[\"build\"]\n\"rustc-workspace-wrapper\" = \"/tmp/anything\"\n",
            "build.rustc-wrapper = \"/tmp/anything\"\n",
            "build = { rustc-wrapper = \"/tmp/anything\" }\n",
            "[target.'cfg(all())']\nlinker = \"/tmp/anything\"\n",
            "[target.x86_64-unknown-linux-gnu]\nrunner = \"/tmp/anything\"\n",
            "target = { \"cfg(all())\" = { linker = \"/tmp/anything\" } }\n",
            "[net]\ngit-fetch-with-cli = true\n",
            "[registry]\ncredential-provider = \"/tmp/anything\"\n",
            "[credential-alias]\nmine = [\"/tmp/anything\"]\n",
        ] {
            assert!(
                program_naming_key(configuration).is_some(),
                "read as naming nothing: {configuration}"
            );
        }
    }

    /// A configuration that only changes where things are put or how they are
    /// compiled names no program, and a tree carrying one is read rather than
    /// declined.
    #[test]
    fn a_configuration_that_starts_nothing_is_not_read_as_naming_a_program() {
        assert_eq!(
            program_naming_key(
                "[build]\ntarget-dir = \"target\"\nrustflags = [\"-C\", \"debuginfo=0\"]\n\n\
                 [net]\noffline = true\n\n[term]\nverbose = false\n\n\
                 [env]\nMY_LINKER = \"anything\"\n"
            ),
            None
        );
    }

    /// The key a tree is declined over is the one it wrote, so whoever reads
    /// the refusal can open the file and see it.
    #[test]
    fn the_key_a_tree_is_declined_over_is_the_one_it_wrote() {
        assert_eq!(
            program_naming_key("[build]\nrustc-wrapper = \"./marker\"\n").as_deref(),
            Some("build.rustc-wrapper")
        );
    }
}
