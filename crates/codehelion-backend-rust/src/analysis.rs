//! Loading a Cargo workspace and reading what the compiler knows about it.
//!
//! # Nothing here runs the project's code unless the request said so
//!
//! One value decides it, and it arrives in the request: [`Permissions`] is
//! built from what the client permitted and from nothing else. There is no
//! default that grants anything, no setting to get wrong and no path that
//! reaches an executing configuration without a permission having travelled to
//! this process — a run that permits nothing and a build of this program that
//! could not execute at all behave identically.
//!
//! Starting a procedural-macro server is not among the things a permission can
//! turn on here: this helper does not offer that class at all, so a person who
//! permits it is told rather than left with a thinner answer than they asked
//! for.
//!
//! # And an untrusted request is answered from inside its boundary or not at
//! all
//!
//! A request may carry a [`ReadBoundary`], and then every path this analysis
//! resolves for itself has to land under it: the file, its package manifest,
//! and the workspace manifest the package is read through. What each of those
//! costs to check is what deciding to decline costs; nothing outside the
//! boundary reaches an answer. See [`crate::boundary`] for what a boundary does
//! not cover.
//!
//! The cost of refusing is visible rather than hidden. A crate with a build
//! script nobody permitted is reported as
//! [`Unavailability::RequiresExecution`] instead of being analysed with
//! whatever happens to resolve, because a build script can generate types the
//! rest of the crate is written against, and there is no way to tell from
//! outside how much of an answer is missing.
//!
//! # Which compiler answers
//!
//! This program's own, bundled as a library — not the one the project builds
//! with. So the toolchain it reports is its own, and the question a handshake
//! settles is whether it can analyse a project rather than whether it matches
//! it.
//!
//! That is a claim about a program on disk, not only about a version string.
//! Cargo reads a configuration file out of the directory it is started in, and
//! the directory it is started in for a target workspace is inside that
//! workspace, so `build.rustc` and the `build.rustc-wrapper` keys beside it are
//! a tree naming a program to run as whoever started this process. The
//! environment in [`compiler_environment`] settles which program that is before
//! any of it is read, on every path, including the first handshake — where no
//! permission has been negotiated yet and none can therefore have been given.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use codehelion_helper::ir::{
    Anchor, CompilerIr, ResolvedSymbol, ResolvedType, SourceRange, SymbolKind, Unavailability,
    UnitRef,
};
use codehelion_helper::protocol::{BuildDescription, Execution};
use ra_ap_hir::{Adt, Crate, HasSource, HirFileId, ModuleDef};
use ra_ap_ide_db::RootDatabase;
use ra_ap_ide_db::base_db::SourceDatabase;
use ra_ap_syntax::AstNode;
use ra_ap_vfs::Vfs;

use crate::boundary::ReadBoundary;
use crate::types::category;
use crate::{calls, constructs, expansions, instantiations, occurrences};

/// A workspace that has been read, kept so a second request about the same
/// project does not pay to read it again.
pub(crate) struct Loaded {
    pub(crate) db: RootDatabase,
    pub(crate) vfs: Vfs,
    pub(crate) root: PathBuf,
}

/// The helper's installed toolchain, fixed before any target workspace is
/// inspected. The absolute sysroot tells rustup proxies to ignore a target
/// repository's `rust-toolchain.toml`.
#[derive(Clone)]
struct HelperToolchain {
    cargo: PathBuf,
    /// The compiler every Cargo this process starts is told to run, so that
    /// naming one is never left to a file in the tree being read.
    rustc: PathBuf,
    rustup_toolchain: String,
}

static HELPER_TOOLCHAIN: OnceLock<Result<HelperToolchain, String>> = OnceLock::new();

/// The toolchain this helper itself was built with, recorded by the build
/// script rather than read from a target tree.
const HELPER_TOOLCHAIN_CHANNEL: &str = env!("CODEHELION_HELPER_TOOLCHAIN");

fn helper_toolchain() -> Result<HelperToolchain, String> {
    HELPER_TOOLCHAIN
        .get_or_init(discover_helper_toolchain)
        .clone()
}

/// Find the toolchain this helper analyses with, before it offers to.
///
/// Every capability this program names at the handshake is answered by a
/// compiler it locates rather than links, so locating one is part of being able
/// to make the offer. A helper that shook hands and then declined each request
/// for want of a toolchain would have `doctor` report a working semantic
/// analysis on a machine where no scan can get one, and leave the scan to
/// discover it.
///
/// The result is kept, so a request pays nothing for having been checked here.
///
/// # Errors
///
/// Returns why the toolchain could not be located or could not answer.
pub(crate) fn require_toolchain() -> Result<(), String> {
    helper_toolchain().map(|_| ())
}

#[allow(
    clippy::disallowed_types,
    reason = "this compiler helper is the designated subprocess isolation boundary"
)]
fn discover_helper_toolchain() -> Result<HelperToolchain, String> {
    let rustup = resolve_tool(ra_ap_toolchain::Tool::Rustup)?;
    let working_directory = tempfile::tempdir()
        .map_err(|error| format!("creating an isolated toolchain directory: {error}"))?;
    let channel = HELPER_TOOLCHAIN_CHANNEL;
    let cargo = rustup_tool(&rustup, channel, "cargo", working_directory.path())?;
    let rustc = rustup_tool(&rustup, channel, "rustc", working_directory.path())?;
    let output = std::process::Command::new(&rustc)
        .args(["--print", "sysroot"])
        .current_dir(working_directory.path())
        .output()
        .map_err(|error| format!("could not start helper Rustc: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "helper Rustc could not report its installed sysroot: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let sysroot = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let sysroot = sysroot.canonicalize().map_err(|error| {
        format!(
            "resolving helper Rustc sysroot {}: {error}",
            sysroot.display()
        )
    })?;
    if !sysroot.is_dir() {
        return Err(format!(
            "helper Rustc sysroot {} is not a directory",
            sysroot.display()
        ));
    }
    Ok(HelperToolchain {
        cargo,
        rustc,
        rustup_toolchain: sysroot.display().to_string(),
    })
}

#[allow(
    clippy::disallowed_types,
    reason = "this compiler helper is the designated subprocess isolation boundary"
)]
fn rustup_tool(
    rustup: &Path,
    channel: &str,
    tool: &str,
    working_directory: &Path,
) -> Result<PathBuf, String> {
    let output = std::process::Command::new(rustup)
        .args(["which", tool])
        .current_dir(working_directory)
        .env("RUSTUP_TOOLCHAIN", channel)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .output()
        .map_err(|error| format!("could not locate helper {tool}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not locate helper {tool} for toolchain {channel}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    path.canonicalize().map_err(|error| {
        format!(
            "resolving helper {tool} executable {}: {error}",
            path.display()
        )
    })
}

/// Locate a tool, keeping the name it was found under.
///
/// The link is deliberately left unresolved. `rustup` is a multi-call binary
/// that decides which program to be from the name it was started as, and some
/// distributions install it as a link to `rustup-init`. Resolving that link
/// turns every query into the installer, which answers a request to locate a
/// toolchain by printing its own usage. `is_file` follows the link, so a name
/// pointing at nothing is still reported here rather than at the first
/// spawn.
fn resolve_tool(tool: ra_ap_toolchain::Tool) -> Result<PathBuf, String> {
    executable_named(tool.path().into_std_path_buf(), tool.name())
}

/// Confirm a located tool can be started, returning the path unchanged.
fn executable_named(path: PathBuf, tool: &str) -> Result<PathBuf, String> {
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "helper {tool} executable {} is not a file",
            path.display()
        ))
    }
}

/// What a request permitted this process to run out of the project.
///
/// One field, because one class is all this helper acts on. A permission it
/// does not act on never reaches here: the handshake says what it will do, and
/// granting anything else is refused where somebody can be told.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Permissions {
    /// Whether build scripts may be run and their output read.
    pub(crate) build_scripts: bool,
}

impl Permissions {
    /// What `permitted` allows, ignoring classes this helper does not act on.
    pub(crate) fn of(permitted: &[Execution]) -> Self {
        Self {
            build_scripts: permitted.contains(&Execution::BuildScript),
        }
    }
}

/// Every workspace this process has read, by the manifest that identifies it
/// and the permissions it was read under.
///
/// Keyed by both, because a workspace read with its build scripts run is not
/// the same reading as one read without them: a cache on the path alone would
/// answer a permitted request from a refused reading, or the reverse.
#[derive(Default)]
pub(crate) struct Workspaces {
    loaded: BTreeMap<(PathBuf, Permissions), Result<Loaded, String>>,
    described: BTreeMap<PathBuf, Result<BuildDescription, String>>,
}

/// Why a unit could not be analysed, or the analysis itself.
pub(crate) enum Outcome {
    /// What the compiler knows.
    Analyzed(Box<CompilerIr>),
    /// Nothing can be known, and why.
    Unavailable {
        /// The reason a run files the unit under, which travels on the wire.
        reason: Unavailability,
        /// Which of the situations behind that reason this was.
        ///
        /// Several of them stand for more than one: a file with no project
        /// above it, a project outside the boundary the request set and a
        /// crate the workspace does not build all arrive as
        /// [`Unavailability::NoBuildInformation`], and a run that sees only
        /// the reason cannot tell somebody which happened.
        why: String,
    },
}

impl Outcome {
    /// A unit that cannot be analysed, for `why`.
    fn unavailable(reason: Unavailability, why: impl Into<String>) -> Self {
        Self::Unavailable {
            reason,
            why: why.into(),
        }
    }
}

impl Workspaces {
    /// What the code under `root` is analysed under.
    ///
    /// `Ok(None)` when there is no Cargo project here at all, which is a thing
    /// this can say rather than a failure to say anything: a tree with no
    /// manifest has no build to be described, and every answer about it will
    /// be the same one.
    ///
    /// Read from `cargo metadata` and the compiler's own `--print cfg` before
    /// loading the workspace, so a request with no project can be declined
    /// without constructing compiler state.
    pub(crate) fn describe(&mut self, root: &Path) -> Result<Option<BuildDescription>, String> {
        let Some(manifest) = nearest_manifest(root, None) else {
            return Ok(None);
        };
        let workspace = workspace_manifest(&manifest);
        self.described
            .entry(workspace.clone())
            .or_insert_with(|| describe_workspace(&workspace))
            .clone()
            .map(Some)
    }

    /// Analyse one crate of one workspace, running only what `permitted` says
    /// and reading only inside `boundary`.
    pub(crate) fn analyze(
        &mut self,
        unit: &UnitRef,
        permitted: Permissions,
        boundary: Option<&Path>,
    ) -> Outcome {
        let boundary = boundary.map(ReadBoundary::new);
        let boundary = boundary.as_ref();
        let anchor = Path::new(&unit.file);
        // The file itself, before anything is resolved from it: a request for a
        // file outside the boundary has no answer that respects the boundary.
        if !within(anchor, boundary) {
            return Outcome::unavailable(
                Unavailability::NoBuildInformation,
                format!(
                    "{} is outside the directory this request confined reading to",
                    unit.file
                ),
            );
        }
        let Some(manifest) = nearest_manifest(anchor, boundary) else {
            return Outcome::unavailable(
                Unavailability::NoBuildInformation,
                format!("no Cargo manifest governs {}", unit.file),
            );
        };
        // The package's own manifest decides this, not the workspace's: one
        // member having a build script says nothing about its neighbours.
        if !permitted.build_scripts && has_build_script(&manifest) {
            return Outcome::unavailable(
                Unavailability::RequiresExecution,
                format!(
                    "{} declares a build script, and nothing permitted running it",
                    manifest.display()
                ),
            );
        }
        // Loaded and cached by workspace rather than by package. Reading a
        // member reads the whole workspace anyway, so keying on the member
        // would read the same thing once per member — and would report every
        // path relative to the member it was asked through, which is not how
        // the project spells it.
        let root = workspace_manifest(&manifest);
        // A package whose workspace sits outside the boundary is declined
        // rather than read: the workspace manifest names the members, the
        // profiles and the patched dependencies the package is compiled with,
        // so an answer about this package is an answer about that file too.
        if !within(&root, boundary) {
            return Outcome::unavailable(
                Unavailability::NoBuildInformation,
                format!(
                    "the workspace manifest {} is outside the directory this request confined reading to",
                    root.display()
                ),
            );
        }
        // A workspace is read from inside itself, so the Cargo configuration
        // beside it is the one Cargo obeys, and the keys in it name programs to
        // start. Nothing named there is ever started without a permission —
        // [`compiler_environment`] settles that on its own — and a tree that
        // names one is told so rather than read under a configuration this
        // process disabled behind its back.
        if !permitted.build_scripts
            && let Some(named) = program_named_by(root.parent().unwrap_or(&root))
        {
            return Outcome::unavailable(
                Unavailability::RequiresExecution,
                format!(
                    "{} sets {}, which names a program for Cargo to run, and nothing permitted running it",
                    named.file.display(),
                    named.key
                ),
            );
        }
        let loaded = self
            .loaded
            .entry((root.clone(), permitted))
            .or_insert_with(|| load(&root, permitted));
        match loaded {
            Err(why) => Outcome::unavailable(
                Unavailability::MetadataUnavailable,
                format!("{}: {why}", root.display()),
            ),
            Ok(loaded) => ra_ap_hir::attach_db(&loaded.db, || analyze_crate(loaded, unit)),
        }
    }
}

/// Whether an answer may be built from `path`.
///
/// True for every path when no boundary was set, which is what a trusted scan
/// asks for: the project decides where its own manifests are.
fn within(path: &Path, boundary: Option<&ReadBoundary>) -> bool {
    boundary.is_none_or(|boundary| boundary.holds(path))
}

/// The `Cargo.toml` governing `path`, found by walking up from it.
///
/// The walk stops at `boundary` rather than climbing past it and being refused
/// afterwards. The two decline the same requests; only this one leaves the
/// directories above a boundary unread.
fn nearest_manifest(path: &Path, boundary: Option<&ReadBoundary>) -> Option<PathBuf> {
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
fn workspace_manifest(manifest: &Path) -> PathBuf {
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
fn has_build_script(manifest: &Path) -> bool {
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
struct NamedProgram {
    /// The file that names it, which is a file in the tree.
    file: PathBuf,
    /// The key that names it, spelled as a person would look it up.
    key: String,
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
fn program_named_by(root: &Path) -> Option<NamedProgram> {
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

/// How this process reads a project, wherever it reads one.
///
/// One value, so that what a run is told it was analysed under and what it was
/// actually analysed under cannot drift apart: the description below and the
/// load above are two readings of the same configuration.
fn cargo_config(
    toolchain: &HelperToolchain,
    permitted: Permissions,
) -> ra_ap_project_model::CargoConfig {
    ra_ap_project_model::CargoConfig {
        // Without the standard library almost every type resolves to nothing,
        // and evidence made of unknowns is worse than no evidence: it looks
        // like agreement.
        sysroot: Some(ra_ap_project_model::RustLibSource::Discover),
        // Resolving a target project is part of reading it. It must neither
        // contact a registry. `project_workspace` first proves that Cargo can
        // read this project with `--offline --locked`; rust-analyzer then
        // redirects its own offline read to an isolated lockfile copy. The
        // metadata list is separate because rust-analyzer forwards it
        // independently.
        extra_args: vec!["--offline".to_owned()],
        metadata_extra_args: vec!["--offline".to_owned()],
        extra_env: [
            (
                "RUSTUP_TOOLCHAIN".to_owned(),
                Some(toolchain.rustup_toolchain.clone()),
            ),
            ("RUSTUP_AUTO_INSTALL".to_owned(), Some("0".to_owned())),
            // Do not let a caller-provided shared target directory reuse a
            // build script from another workspace. Build-script outputs are
            // workspace-specific (notably OUT_DIR), so Cargo must choose a
            // target directory owned by the project being analysed.
            ("CARGO_TARGET_DIR".to_owned(), None),
        ]
        .into_iter()
        .chain(compiler_environment(toolchain, permitted))
        .collect(),
        ..ra_ap_project_model::CargoConfig::default()
    }
}

/// Which program every Cargo started for a target workspace runs as the
/// compiler, and which it does not run around it.
///
/// Cargo finds `.cargo/config.toml` by walking up from the directory it was
/// started in, and a target workspace is where it has to be started for its own
/// metadata to be the metadata that comes back. So the tree decides what that
/// file says, and the keys in it name programs: `build.rustc` is the compiler
/// itself, and `build.rustc-wrapper` is a program Cargo runs with the compiler
/// as its first argument. Either is somebody else's code running as whoever
/// started this scan, and both are read long before a permission has been asked
/// for — the handshake that describes a build reads that file too.
///
/// An environment variable outranks the file for all four keys, so naming the
/// compiler here is what settles it. Cargo spells "no wrapper" as an empty
/// wrapper, which is why the wrappers are set rather than removed: removing
/// them would leave the file's own value in force.
///
/// The wrappers come back when build scripts are permitted, because that
/// permission is the tree's own build being run on purpose and a wrapper is
/// part of how the tree builds. The compiler stays this program's own either
/// way: what a type resolved to is a fact about the compiler that resolved it,
/// and a permission to run a build script is not a request to be answered by a
/// different compiler.
fn compiler_environment(
    toolchain: &HelperToolchain,
    permitted: Permissions,
) -> Vec<(String, Option<String>)> {
    let rustc = toolchain.rustc.display().to_string();
    let mut environment = vec![
        ("RUSTC".to_owned(), Some(rustc.clone())),
        ("CARGO_BUILD_RUSTC".to_owned(), Some(rustc)),
    ];
    if !permitted.build_scripts {
        for key in [
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ] {
            environment.push((key.to_owned(), Some(String::new())));
        }
    }
    environment
}

/// Build the project-model configuration used for an actual workspace load.
///
/// The project-model metadata adapter currently translates an absent value in
/// `extra_env` into an empty environment value. Keep the canonical config's
/// `None` (which the toolchain command correctly interprets as removal), then
/// give metadata and build-script commands an explicit target under the
/// workspace. This preserves the isolation promised by the removal while
/// avoiding an invalid empty `CARGO_TARGET_DIR` in that adapter.
fn cargo_config_for_workspace(
    toolchain: &HelperToolchain,
    manifest: &Path,
    permitted: Permissions,
) -> ra_ap_project_model::CargoConfig {
    let mut config = cargo_config(toolchain, permitted);
    if let Some(workspace_root) = manifest.parent() {
        config.extra_env.insert(
            "CARGO_TARGET_DIR".to_owned(),
            Some(workspace_root.join("target").display().to_string()),
        );
    }
    config
}

/// How many times this process has called
/// [`ra_ap_project_model::ProjectWorkspace::load`] and had it succeed.
///
/// Test-only. The invariant a request must keep is a cost — reading a
/// workspace's `cargo metadata` and sysroot once rather than twice — and a
/// cost is not visible by reading the source that is supposed to enforce it.
/// A counter around the one call site in this file that reaches the real load
/// is what lets a test observe the cost a request actually paid.
#[cfg(test)]
static PROJECT_WORKSPACE_LOADS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn project_workspace(
    manifest: &Path,
    permitted: Permissions,
) -> Result<ra_ap_project_model::ProjectWorkspace, String> {
    let toolchain = helper_toolchain()?;
    project_workspace_with_toolchain(manifest, &toolchain, permitted)
}

fn project_workspace_with_toolchain(
    manifest: &Path,
    toolchain: &HelperToolchain,
    permitted: Permissions,
) -> Result<ra_ap_project_model::ProjectWorkspace, String> {
    verify_locked_offline_metadata(manifest, toolchain)?;
    let path = manifest
        .to_str()
        .and_then(|path| ra_ap_vfs::AbsPathBuf::try_from(path).ok())
        .ok_or_else(|| {
            format!(
                "the manifest path is not absolute utf-8: {}",
                manifest.display()
            )
        })?;
    let found = ra_ap_project_model::ProjectManifest::from_manifest_file(path)
        .map_err(|error| error.to_string())?;
    let workspace = ra_ap_project_model::ProjectWorkspace::load(
        found,
        &cargo_config_for_workspace(toolchain, manifest, permitted),
        &|_| {},
    )
    .map_err(|error| error.to_string())?;
    #[cfg(test)]
    PROJECT_WORKSPACE_LOADS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let ra_ap_project_model::ProjectWorkspaceKind::Cargo {
        error: Some(error), ..
    } = &workspace.kind
    {
        return Err(format!(
            "Cargo metadata requires a local locked dependency resolution: {error}"
        ));
    }
    Ok(workspace)
}

/// Prove that Cargo can resolve the project without either network access or a
/// lockfile update before rust-analyzer loads it through its isolated copy.
///
/// Run from a directory of its own rather than from the project, so the
/// configuration this Cargo reads is not one the project wrote. The compiler
/// environment goes with it regardless: a directory outside the tree settles
/// which files are read and says nothing about what this process inherited.
#[allow(
    clippy::disallowed_types,
    reason = "this compiler helper is the designated subprocess isolation boundary"
)]
fn verify_locked_offline_metadata(
    manifest: &Path,
    toolchain: &HelperToolchain,
) -> Result<(), String> {
    // Named, so the directory outlives the command that runs in it.
    let working_directory = tempfile::tempdir()
        .map_err(|error| format!("creating an isolated Cargo working directory: {error}"))?;
    let mut command = std::process::Command::new(&toolchain.cargo);
    command
        .args([
            "metadata",
            "--format-version=1",
            "--offline",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
        .current_dir(working_directory.path())
        .env("RUSTUP_TOOLCHAIN", &toolchain.rustup_toolchain)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env_remove("CARGO_TARGET_DIR");
    // Nothing is compiled to answer this, so nothing here is permitted to run
    // whatever a wrapper would have been.
    for (key, value) in compiler_environment(toolchain, Permissions::default()) {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    let output = command
        .output()
        .map_err(|error| format!("could not start Cargo metadata: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "Cargo metadata requires a local locked dependency resolution: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// What the workspace at `manifest` is read under.
///
/// A member's own features and those of its direct dependencies. A direct
/// dependency's feature selection lives in the member's manifest, yet it does
/// not necessarily change `Cargo.lock`; omitting it could therefore merge two
/// different resolved programs. Transitive packages remain out: their feature
/// sets are derived from the direct selections and the lockfile, and recording
/// every resolver-internal choice would split a variant when Cargo changes an
/// irrelevant implementation detail.
///
/// Read under no permission at all, because none has been asked for yet: a
/// build is described before a run knows whether it will analyse anything, and
/// a request to describe one carries nothing that could permit running it.
fn describe_workspace(manifest: &Path) -> Result<BuildDescription, String> {
    let workspace = project_workspace(manifest, Permissions::default())?;
    let mut cfgs: Vec<String> = workspace
        .rustc_cfg
        .iter()
        .map(ToString::to_string)
        .collect();
    let mut features = Vec::new();
    if let ra_ap_project_model::ProjectWorkspaceKind::Cargo { cargo, .. } = &workspace.kind {
        for package in cargo.packages() {
            let data = &cargo[package];
            if !data.is_member {
                continue;
            }
            for feature in &data.active_features {
                features.push(format!("{}/{feature}", data.name));
            }
            for dependency in &data.dependencies {
                let dependency = &cargo[dependency.pkg];
                for feature in &dependency.active_features {
                    features.push(format!("{}/{feature}", dependency.name));
                }
            }
        }
    }
    cfgs.sort();
    cfgs.dedup();
    features.sort();
    features.dedup();
    Ok(BuildDescription { features, cfgs })
}

/// Settings for turning a read [`ra_ap_project_model::ProjectWorkspace`] into
/// the crate graph and VFS a request answers from.
///
/// Its own function so a test can build the identical value without
/// duplicating the reasoning beside each field.
const fn load_cargo_config(permitted: Permissions) -> ra_ap_load_cargo::LoadCargoConfig {
    ra_ap_load_cargo::LoadCargoConfig {
        // The one setting here that runs the project's code, and the only
        // thing that turns it on is a permission that travelled with the
        // request. Running build scripts is what makes the output directory
        // they wrote readable, which is the whole of what permitting them buys.
        load_out_dirs_from_check: permitted.build_scripts,
        // Not reachable by any permission: starting a procedural-macro server
        // is a class this helper does not offer, so nobody can be under the
        // impression they turned it on.
        with_proc_macro_server: ra_ap_load_cargo::ProcMacroServerChoice::None,
        prefill_caches: false,
        num_worker_threads: 1,
        proc_macro_processes: 0,
    }
}

fn load(manifest: &Path, permitted: Permissions) -> Result<Loaded, String> {
    let toolchain = helper_toolchain()?;
    let config = cargo_config_for_workspace(&toolchain, manifest, permitted);
    let load_config = load_cargo_config(permitted);
    let root = manifest
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    // Read the workspace once and carry the result forward, instead of
    // reading it here only to have `ra_ap_load_cargo::load_workspace_at`
    // read it again from scratch: `cargo metadata` and sysroot discovery are
    // the expensive part of a semantic scan, and a large workspace paying for
    // them twice is time taken straight out of `helper-timeout-ms`. Running
    // the build scripts and handing the workspace to `load_workspace` is
    // exactly what `load_workspace_at` does internally, minus its own
    // `ProjectWorkspace::load`.
    let mut workspace = project_workspace_with_toolchain(manifest, &toolchain, permitted)?;
    if load_config.load_out_dirs_from_check {
        let build_scripts = workspace
            .run_build_scripts(&config, &|_| {})
            .map_err(|error| error.to_string())?;
        workspace.set_build_scripts(build_scripts);
    }
    let (db, vfs, _proc_macro) =
        ra_ap_load_cargo::load_workspace(workspace, &config.extra_env, &load_config)
            .map_err(|error| error.to_string())?;
    Ok(Loaded { db, vfs, root })
}

/// Everything the compiler knows about one crate, collected into the wire IR.
fn analyze_crate(loaded: &Loaded, unit: &UnitRef) -> Outcome {
    let db = &loaded.db;
    let requested_path = Path::new(&unit.file);
    let Some(requested_id) = file_of(loaded, requested_path) else {
        return Outcome::unavailable(
            Unavailability::NoBuildInformation,
            format!(
                "the workspace at {} holds no file called {}",
                loaded.root.display(),
                unit.file
            ),
        );
    };
    // Spelled from the file the workspace resolved the request to, not from the
    // path the request arrived as. Every anchor below is spelled from the
    // workspace's own copy, and this string decides by equality which of them
    // belong to the requested file: derived from the caller's spelling it would
    // be a second rendering of the same file that only has to agree, and one
    // that names a separator differently agrees on no symbol at all.
    let requested_file = loaded
        .vfs
        .file_path(requested_id)
        .as_path()
        .map(|path| codehelion_helper::ir::spell(Some(&loaded.root), Path::new(path.as_str())))
        .unwrap_or_default();
    let Some(krate) = Crate::all(db).into_iter().find(|krate| {
        krate
            .display_name(db)
            .is_some_and(|name| name.to_string() == unit.unit)
    }) else {
        return Outcome::unavailable(
            Unavailability::NoBuildInformation,
            format!(
                "the workspace at {} builds no crate called {}",
                loaded.root.display(),
                unit.unit
            ),
        );
    };

    let mut ir = CompilerIr::empty(unit.clone());
    ir.anchored_at = Some(loaded.root.display().to_string());
    let mut types = TypeTable::default();
    let mut modules = vec![krate.root_module(db)];
    while let Some(module) = modules.pop() {
        modules.extend(module.children(db));
        for definition in module.declarations(db) {
            collect(
                loaded,
                definition,
                None,
                &requested_file,
                &mut ir,
                &mut types,
            );
        }
    }
    // What the macros invoked in this file declared. The walk above passes
    // those over, because a declaration inside an expansion has no place in a
    // file until somebody says which invocation it came out of.
    let macros = expansions::collect(loaded, Path::new(&unit.file), &mut types);
    for expanded in macros.expanded {
        collect(
            loaded,
            expanded.definition,
            Some(&expanded.anchor),
            &requested_file,
            &mut ir,
            &mut types,
        );
    }
    ir.unexpanded_macros = macros.unexpanded;
    // Names, after declarations, so that a name occurring exactly where a
    // declaration begins is dropped rather than recorded twice. That can only
    // happen where the declaration opens with its own name — a field, and
    // nothing else — so the entry that survives is the one that says more.
    let declared: BTreeSet<(String, u64)> = ir.symbols.iter().map(place).collect();
    for occurrence in occurrences::collect(loaded, Path::new(&unit.file), &mut types) {
        if !declared.contains(&place(&occurrence)) {
            ir.symbols.push(occurrence);
        }
    }
    ir.instantiations = instantiations::collect(loaded, Path::new(&unit.file), krate, &mut types);
    ir.calls = calls::collect(loaded, Path::new(&unit.file));
    ir.semantic_constructs = constructs::collect(loaded, Path::new(&unit.file));
    ir.effects = codehelion_helper::effects::summarize(&ir.semantic_constructs);
    ir.data_flow = crate::data_flow::collect(loaded, Path::new(&unit.file), &ir.calls);
    ir.calls.extend(macros.calls);
    ir.expressions = macros.expressions;
    ir.calls.sort_by_key(|call| {
        (
            call.anchor.expansion.start_byte,
            call.anchor.expansion.end_byte,
        )
    });
    ir.types = types.finish();
    // Sorted so that two runs over one unchanged workspace produce the same
    // document: the module walk above visits in whatever order the database
    // hands things back.
    ir.symbols.sort_by(|a, b| {
        (
            &a.anchor.expansion.file,
            a.anchor.expansion.start_byte,
            &a.id,
        )
            .cmp(&(
                &b.anchor.expansion.file,
                b.anchor.expansion.start_byte,
                &b.id,
            ))
    });
    Outcome::Analyzed(Box::new(ir))
}

/// Where a symbol sits, which is what makes two entries the same entry.
fn place(symbol: &ResolvedSymbol) -> (String, u64) {
    (
        symbol.anchor.expansion.file.clone(),
        symbol.anchor.expansion.start_byte,
    )
}

/// Keep one declaration for each compiler symbol when the module walk and an
/// explicit macro-expansion walk both reached it.
///
/// Rust-analyzer can expose an item from a declarative macro through a module
/// declaration as well as through the expansion tree. The latter carries the
/// invocation-to-definition anchor the protocol promises, so it wins over an
/// otherwise identical ordinary anchor. Different declarations cannot share
/// this key inside a well-formed crate; their module path is part of `id`.
/// Add what the compiler knows about one declaration to `ir`.
///
/// `origin` is set for a declaration a macro produced. Everything it declares
/// — the item, and the fields inside it — anchors at the invocation, because
/// that is the only place in a file any of it can be pointed at.
fn collect(
    loaded: &Loaded,
    definition: ModuleDef,
    origin: Option<&Anchor>,
    requested_file: &str,
    ir: &mut CompilerIr,
    types: &mut TypeTable,
) {
    let db = &loaded.db;
    match definition {
        ModuleDef::Function(function) => {
            let Some(anchor) = anchored(loaded, origin, function.source(db)) else {
                return;
            };
            if anchor.expansion.file != requested_file {
                return;
            }
            let returns = types.intern(&function.ret_type(db), db);
            ir.symbols.push(ResolvedSymbol {
                id: path_of(function.name(db).as_str(), function.module(db), db),
                name: function.name(db).as_str().to_string(),
                kind: SymbolKind::Function,
                anchor,
                type_index: Some(returns),
                // Every declaration collected here is one this crate holds. A
                // use that resolves elsewhere is a different question, asked of
                // occurrences rather than of definitions.
                external: false,
            });
        }
        ModuleDef::Adt(adt) => {
            let name = adt.name(db).as_str().to_string();
            let Some(anchor) = adt_anchor(loaded, origin, adt) else {
                return;
            };
            if anchor.expansion.file != requested_file {
                return;
            }
            ir.symbols.push(ResolvedSymbol {
                id: path_of(&name, adt.module(db), db),
                name: name.clone(),
                kind: SymbolKind::Type,
                anchor,
                type_index: None,
                external: false,
            });
            if let Adt::Struct(structure) = adt {
                for field in structure.fields(db) {
                    let Some(anchor) = anchored(loaded, origin, field.source(db)) else {
                        continue;
                    };
                    let field_name = field.name(db).as_str().to_string();
                    let index = types.intern(&field.ty(db), db);
                    ir.symbols.push(ResolvedSymbol {
                        id: format!("{}::{field_name}", path_of(&name, adt.module(db), db)),
                        name: field_name,
                        kind: SymbolKind::Field,
                        anchor,
                        type_index: Some(index),
                        external: false,
                    });
                }
            }
        }
        ModuleDef::Const(konst) => {
            let Some(anchor) = anchored(loaded, origin, konst.source(db)) else {
                return;
            };
            if anchor.expansion.file != requested_file {
                return;
            }
            let name = konst
                .name(db)
                .map(|name| name.as_str().to_string())
                .unwrap_or_default();
            let index = types.intern(&konst.ty(db), db);
            ir.symbols.push(ResolvedSymbol {
                id: path_of(&name, konst.module(db), db),
                name,
                kind: SymbolKind::Constant,
                anchor,
                type_index: Some(index),
                external: false,
            });
        }
        ModuleDef::Static(statik) => {
            let Some(anchor) = anchored(loaded, origin, statik.source(db)) else {
                return;
            };
            if anchor.expansion.file != requested_file {
                return;
            }
            let name = statik.name(db).as_str().to_string();
            let index = types.intern(&statik.ty(db), db);
            ir.symbols.push(ResolvedSymbol {
                id: path_of(&name, statik.module(db), db),
                name,
                kind: SymbolKind::Constant,
                anchor,
                type_index: Some(index),
                external: false,
            });
        }
        _ => {}
    }
}

fn adt_anchor(loaded: &Loaded, origin: Option<&Anchor>, adt: Adt) -> Option<Anchor> {
    origin
        .cloned()
        .or_else(|| adt_range(loaded, adt).map(Anchor::written_here))
}

/// Where a type was written.
pub(crate) fn adt_range(loaded: &Loaded, adt: Adt) -> Option<SourceRange> {
    let db = &loaded.db;
    match adt {
        Adt::Struct(item) => definition_range(loaded, item.source(db)),
        Adt::Enum(item) => definition_range(loaded, item.source(db)),
        Adt::Union(item) => definition_range(loaded, item.source(db)),
    }
}

/// Where a declaration is, given what it came out of.
fn anchored<T: AstNode>(
    loaded: &Loaded,
    origin: Option<&Anchor>,
    source: Option<ra_ap_hir::InFile<T>>,
) -> Option<Anchor> {
    origin.cloned().or_else(|| anchor_of(loaded, source))
}

/// The path a definition is known by, as the compiler spells it.
pub(crate) fn path_of(name: &str, module: ra_ap_hir::Module, db: &RootDatabase) -> String {
    let mut segments: Vec<String> = module
        .path_to_root(db)
        .into_iter()
        .rev()
        .filter_map(|part| part.name(db).map(|name| name.as_str().to_string()))
        .collect();
    let krate = module
        .krate(db)
        .display_name(db)
        .map_or_else(|| "crate".to_string(), |name| name.to_string());
    segments.insert(0, krate);
    segments.push(name.to_string());
    segments.join("::")
}

/// Where a definition sits, in the file it sits in.
///
/// `None` for anything whose source is inside a macro expansion rather than in
/// a file. Reporting it against the expansion site would place a definition
/// nobody wrote at a location somebody did, which is exactly the confusion the
/// anchor's two halves exist to prevent — and until macro expansion is a
/// capability this helper offers, leaving it out is the honest answer.
fn anchor_of<T: AstNode>(loaded: &Loaded, source: Option<ra_ap_hir::InFile<T>>) -> Option<Anchor> {
    definition_range(loaded, source).map(Anchor::written_here)
}

/// The range a declaration occupies in a file, if it occupies one.
pub(crate) fn definition_range<T: AstNode>(
    loaded: &Loaded,
    source: Option<ra_ap_hir::InFile<T>>,
) -> Option<SourceRange> {
    let source = source?;
    let file_id = real_file(source.file_id, &loaded.db)?;
    Some(source_range(
        loaded,
        file_id,
        source.value.syntax().text_range(),
    ))
}

/// The file the workspace holds for `path`, if it holds one.
///
/// Compared against what the loader recorded rather than resolved on the
/// filesystem for every candidate: a workspace holds thousands of files, and
/// asking the operating system about each of them to answer one question is a
/// cost paid on every request.
pub(crate) fn file_of(loaded: &Loaded, path: &Path) -> Option<ra_ap_vfs::FileId> {
    let canonical = path.canonicalize().ok();
    loaded.vfs.iter().find_map(|(id, vfs_path)| {
        let candidate = Path::new(vfs_path.as_path()?.as_str());
        (candidate == path || Some(candidate) == canonical.as_deref()).then_some(id)
    })
}

/// A byte range of one file, spelled the way the project spells the file.
///
/// Against the workspace root this process read the project from, which the
/// analysis states in [`CompilerIr::anchored_at`] — the spelling is written and
/// read back by one shared rule rather than by two that have to agree.
pub(crate) fn source_range(
    loaded: &Loaded,
    file_id: ra_ap_vfs::FileId,
    range: ra_ap_syntax::TextRange,
) -> SourceRange {
    let start = u32::from(range.start());
    let text = loaded.db.file_text(file_id).text(&loaded.db).to_string();
    let path = loaded
        .vfs
        .file_path(file_id)
        .as_path()
        .map(|path| codehelion_helper::ir::spell(Some(&loaded.root), Path::new(path.as_str())))
        .unwrap_or_default();
    SourceRange {
        file: path,
        start_byte: u64::from(start),
        end_byte: u64::from(u32::from(range.end())),
        start_line: line_of(&text, start as usize),
    }
}

pub(crate) fn real_file(file_id: HirFileId, db: &RootDatabase) -> Option<ra_ap_vfs::FileId> {
    file_id.file_id().map(|file| file.file_id(db))
}

/// The one-based line the byte at `offset` falls on.
fn line_of(text: &str, offset: usize) -> u32 {
    let counted = text
        .get(..offset.min(text.len()))
        .map_or(0, |head| head.bytes().filter(|byte| *byte == b'\n').count());
    u32::try_from(counted).unwrap_or(u32::MAX).saturating_add(1)
}

/// The types a unit mentions, each recorded once.
#[derive(Default)]
pub(crate) struct TypeTable {
    seen: BTreeMap<(String, &'static str), u32>,
    entries: Vec<ResolvedType>,
}

impl TypeTable {
    /// The index of `ty` in the table, adding it if this is its first mention.
    pub(crate) fn intern(&mut self, ty: &ra_ap_hir::Type<'_>, db: &RootDatabase) -> u32 {
        let category = category(ty, db);
        let display = display_of(ty, db);
        let key = (display.clone(), category.name());
        if let Some(index) = self.seen.get(&key) {
            return *index;
        }
        let index = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        self.entries.push(ResolvedType {
            display,
            category,
            // Left empty until a use asks for it: filling in every type
            // argument of every type pulls in the whole standard library's
            // generic surface for evidence nothing yet reads.
            arguments: Vec::new(),
            definition: ty.as_adt().map(|adt| adt.name(db).as_str().to_string()),
        });
        self.seen.insert(key, index);
        index
    }

    fn finish(self) -> Vec<ResolvedType> {
        self.entries
    }
}

fn display_of(ty: &ra_ap_hir::Type<'_>, db: &RootDatabase) -> String {
    ty.as_adt().map_or_else(
        || category(ty, db).name().to_string(),
        |adt| adt.name(db).as_str().to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::{
        Declared, Outcome, PROJECT_WORKSPACE_LOADS, Permissions, Workspaces, cargo_config,
        declared_build_script, has_build_script, helper_toolchain, program_naming_key,
    };

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

    /// A located tool keeps the name it was found under, links and all.
    ///
    /// `rustup` is one binary that is several programs, told apart by the name
    /// it was started as. Installations that link `rustup` to `rustup-init`
    /// are ordinary, and following that link hands every toolchain query to
    /// the installer instead.
    ///
    /// Stated where a link can be made without asking permission first. The
    /// systems that cannot are the ones where the installations in question
    /// do not exist either.
    #[test]
    #[cfg(unix)]
    #[allow(clippy::expect_used)] // Test setup requires a writable temporary directory.
    fn a_linked_tool_keeps_the_name_it_was_found_under() {
        use super::executable_named;

        let directory = tempfile::tempdir().expect("a temporary directory");
        let target = directory.path().join("rustup-init");
        std::fs::write(&target, "").expect("writing the link target");
        let link = directory.path().join("rustup");
        std::os::unix::fs::symlink(&target, &link).expect("linking one name to the other");

        assert_eq!(executable_named(link.clone(), "Rustup"), Ok(link));
    }

    /// Fixed when the helper is built, because nothing at run time can supply
    /// it: an empty value would be handed to every rustup proxy, and rustup
    /// answers an empty `RUSTUP_TOOLCHAIN` by selecting whatever the directory
    /// it runs in declares — the one outcome this constant exists to prevent.
    #[test]
    fn the_helper_knows_which_toolchain_it_was_built_with() {
        assert!(
            !super::HELPER_TOOLCHAIN_CHANNEL.trim().is_empty(),
            "the build recorded no toolchain"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // Test setup requires an installed helper toolchain.
    fn rust_analyzer_metadata_is_offline_after_the_locked_preflight() {
        let toolchain = helper_toolchain().expect("helper toolchain is available to tests");
        let config = cargo_config(&toolchain, Permissions::default());
        assert_eq!(config.extra_args, ["--offline"]);
        assert_eq!(config.metadata_extra_args, ["--offline"]);
        assert_eq!(
            config
                .extra_env
                .get("RUSTUP_AUTO_INSTALL")
                .and_then(Option::as_deref),
            Some("0")
        );
        assert_eq!(
            config
                .extra_env
                .get("RUSTUP_TOOLCHAIN")
                .and_then(Option::as_deref),
            Some(toolchain.rustup_toolchain.as_str())
        );
        assert_eq!(config.extra_env.get("CARGO_TARGET_DIR"), Some(&None));
    }

    /// Which program runs as the compiler is settled before a project is read,
    /// including for the description a handshake asks for — where no permission
    /// exists yet, so none can have allowed the tree to choose.
    #[test]
    #[allow(clippy::expect_used)] // Test setup requires an installed helper toolchain.
    fn a_target_tree_cannot_name_the_program_cargo_runs_as_the_compiler() {
        let toolchain = helper_toolchain().expect("helper toolchain is available to tests");
        let config = cargo_config(&toolchain, Permissions::default());
        let named = |key: &str| config.extra_env.get(key).cloned().flatten();

        let rustc = toolchain.rustc.display().to_string();
        assert_eq!(named("RUSTC").as_deref(), Some(rustc.as_str()));
        assert_eq!(named("CARGO_BUILD_RUSTC").as_deref(), Some(rustc.as_str()));
        // Empty rather than absent: Cargo reads an absent wrapper out of the
        // configuration file, which is the file being defended against.
        for key in [
            "RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ] {
            assert_eq!(named(key).as_deref(), Some(""), "{key}");
        }
    }

    /// Permitting build scripts is the tree's own build being run on purpose,
    /// and a wrapper is part of how a tree builds. The compiler itself is still
    /// this program's own, because what a type resolved to is a fact about the
    /// compiler that resolved it.
    #[test]
    #[allow(clippy::expect_used)] // Test setup requires an installed helper toolchain.
    fn permitting_build_scripts_returns_the_wrappers_and_keeps_the_compiler() {
        let toolchain = helper_toolchain().expect("helper toolchain is available to tests");
        let config = cargo_config(
            &toolchain,
            Permissions {
                build_scripts: true,
            },
        );

        assert_eq!(
            config
                .extra_env
                .get("RUSTC")
                .and_then(Option::as_deref)
                .map(str::to_owned),
            Some(toolchain.rustc.display().to_string())
        );
        assert!(!config.extra_env.contains_key("RUSTC_WRAPPER"));
        assert!(!config.extra_env.contains_key("RUSTC_WORKSPACE_WRAPPER"));
    }

    /// Answering one request about a workspace must cost one real read of it.
    ///
    /// Driven end to end through [`Workspaces::analyze`] against a real,
    /// minimal crate, and counted at the one call site in this file that
    /// reaches [`ra_ap_project_model::ProjectWorkspace::load`]: a request that
    /// paid for a second read the way the removed code did would show two
    /// here, whatever the surrounding source happens to read like.
    #[test]
    #[allow(clippy::expect_used)] // Test setup requires an installed helper toolchain.
    fn a_semantic_request_reads_its_workspace_exactly_once() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(
            directory.path().join("Cargo.toml"),
            "[workspace]\nresolver = \"3\"\n\n[package]\nname = \"solo\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("writing a manifest");
        std::fs::write(
            directory.path().join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\n\
             # It is not intended for manual editing.\n\
             version = 4\n\n[[package]]\nname = \"solo\"\nversion = \"0.1.0\"\n",
        )
        .expect("writing a lockfile");
        std::fs::create_dir(directory.path().join("src")).expect("creating a source directory");
        std::fs::write(
            directory.path().join("src/lib.rs"),
            "pub fn answer() -> i32 { 42 }\n",
        )
        .expect("writing a source file");

        let unit = codehelion_helper::ir::UnitRef {
            unit: "solo".to_string(),
            file: directory.path().join("src/lib.rs").display().to_string(),
            variant: "host".to_string(),
        };

        PROJECT_WORKSPACE_LOADS.store(0, Ordering::SeqCst);
        let mut workspaces = Workspaces::default();
        let outcome = workspaces.analyze(&unit, Permissions::default(), None);
        assert!(
            matches!(outcome, Outcome::Analyzed(_)),
            "the fixture crate should analyze cleanly"
        );
        assert_eq!(
            PROJECT_WORKSPACE_LOADS.load(Ordering::SeqCst),
            1,
            "one semantic request must read the workspace exactly once"
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
