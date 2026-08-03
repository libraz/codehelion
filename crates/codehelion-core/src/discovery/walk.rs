//! Filesystem traversal that produces classified source-file candidates.
//!
//! The walk is read-only and never follows symbolic links. It honours
//! `.gitignore` and related ignore files by default so vendored and build
//! output is skipped, and it applies a byte-size ceiling per file. Symbolic
//! links and files that exceed the ceiling are counted, not silently dropped.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use super::language::{
    Classification, HeaderEvidence, HeaderPolicy, Language, LanguageSelection, classify,
};

const CARGO_MANIFEST: &str = "Cargo.toml";
const COMPILE_COMMANDS: &str = "compile_commands.json";

/// A file selected by the walk as a possible source unit.
pub(super) struct Candidate {
    pub(super) relative_path: PathBuf,
    pub(super) absolute_path: PathBuf,
    pub(super) classification: Classification,
}

/// Everything the walk gathered in one pass.
pub(super) struct WalkOutput {
    pub(super) candidates: Vec<Candidate>,
    /// What the tree says about the language its bare `.h` headers belong to.
    ///
    /// Tallied over every C or C++ file the walk saw, including the ones the
    /// language selection then excluded: a project's `.cpp` files still say
    /// its headers are C++ even in a run that analyses only C, and reading
    /// those headers with the C grammar because the evidence was filtered
    /// away is the mistake this exists to avoid.
    pub(super) evidence: HeaderEvidence,
    pub(super) manifests: Vec<PathBuf>,
    pub(super) compile_commands: Vec<PathBuf>,
    /// Files skipped because they exceeded the size ceiling.
    pub(super) too_large: u64,
    /// Source files excluded because their language was disabled.
    pub(super) language_excluded: u64,
    /// Symbolic links deliberately left unresolved by the walker.
    pub(super) symlinks: u64,
    /// Symbolic-link files deliberately left unresolved by the walker.
    pub(super) symlink_files: u64,
    /// Symbolic-link directories deliberately left unresolved by the walker.
    pub(super) symlink_directories: u64,
    /// Directory entries the walker could not read.
    pub(super) walk_errors: u64,
}

/// Settings the walk needs, extracted from the discovery config.
pub(super) struct WalkSettings {
    pub(super) respect_gitignore: bool,
    pub(super) max_file_bytes: u64,
    pub(super) header_policy: HeaderPolicy,
    pub(super) selection: LanguageSelection,
    pub(super) follow_links: bool,
}

/// Traverse `root`, collecting source candidates, Cargo manifests and a
/// compilation database if one is present.
pub(super) fn collect(root: &Path, settings: &WalkSettings) -> WalkOutput {
    let mut output = WalkOutput {
        candidates: Vec::new(),
        evidence: HeaderEvidence::default(),
        manifests: Vec::new(),
        compile_commands: Vec::new(),
        too_large: 0,
        language_excluded: 0,
        symlinks: 0,
        symlink_files: 0,
        symlink_directories: 0,
        walk_errors: 0,
    };

    let mut builder = WalkBuilder::new(root);
    builder.follow_links(settings.follow_links);
    if !settings.respect_gitignore {
        builder
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .ignore(false)
            .parents(false)
            // `--no-ignore` means every path under the requested root. The
            // ignore crate's separate hidden-path filter otherwise still
            // omits dot-directories even after all ignore files are disabled.
            .hidden(false);
    }

    for result in builder.build() {
        let Ok(entry) = result else {
            output.walk_errors += 1;
            continue;
        };
        if !settings.follow_links
            && entry
                .file_type()
                .is_some_and(|file_type| file_type.is_symlink())
        {
            output.symlinks += 1;
            if entry.path().is_dir() {
                output.symlink_directories += 1;
            } else {
                output.symlink_files += 1;
            }
            continue;
        }
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            output.walk_errors += 1;
            continue;
        };
        let byte_len = metadata.len();
        if byte_len > settings.max_file_bytes {
            output.too_large += 1;
            continue;
        }
        match path.file_name().and_then(|n| n.to_str()) {
            Some(CARGO_MANIFEST) => {
                output.manifests.push(path.to_path_buf());
                continue;
            }
            Some(COMPILE_COMMANDS) => {
                output.compile_commands.push(path.to_path_buf());
                continue;
            }
            _ => {}
        }
        let Some(classification) = classify(path, settings.header_policy) else {
            continue;
        };
        output.evidence.observe(classification);
        // A header still awaiting the tree-wide verdict could end up as either
        // language, so it survives the walk while either one is enabled and is
        // filtered again once discovery has settled it.
        let wanted = if classification.provisional {
            settings.selection.includes(Language::C) || settings.selection.includes(Language::Cpp)
        } else {
            settings.selection.includes(classification.language)
        };
        if !wanted {
            output.language_excluded += 1;
            continue;
        }
        let relative_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        output.candidates.push(Candidate {
            relative_path,
            absolute_path: path.to_path_buf(),
            classification,
        });
    }

    output
}
