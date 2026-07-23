//! Filesystem traversal that produces classified source-file candidates.
//!
//! The walk is read-only and never follows symbolic links. It honours
//! `.gitignore` and related ignore files by default so vendored and build
//! output is skipped, and it applies a byte-size ceiling per file. Files that
//! exceed the ceiling are counted, not silently dropped.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use super::language::{Classification, HeaderPolicy, LanguageSelection, classify};

const CARGO_MANIFEST: &str = "Cargo.toml";
const COMPILE_COMMANDS: &str = "compile_commands.json";

/// A file selected by the walk as a possible source unit.
pub(super) struct Candidate {
    pub(super) relative_path: PathBuf,
    pub(super) absolute_path: PathBuf,
    pub(super) classification: Classification,
    pub(super) byte_len: u64,
}

/// Everything the walk gathered in one pass.
pub(super) struct WalkOutput {
    pub(super) candidates: Vec<Candidate>,
    pub(super) manifests: Vec<PathBuf>,
    pub(super) compile_commands: Option<PathBuf>,
    /// Files skipped because they exceeded the size ceiling.
    pub(super) too_large: u64,
    /// Directory entries the walker could not read.
    pub(super) walk_errors: u64,
}

/// Settings the walk needs, extracted from the discovery config.
pub(super) struct WalkSettings {
    pub(super) respect_gitignore: bool,
    pub(super) max_file_bytes: u64,
    pub(super) header_policy: HeaderPolicy,
    pub(super) selection: LanguageSelection,
}

/// Traverse `root`, collecting source candidates, Cargo manifests and a
/// compilation database if one is present.
pub(super) fn collect(root: &Path, settings: &WalkSettings) -> WalkOutput {
    let mut output = WalkOutput {
        candidates: Vec::new(),
        manifests: Vec::new(),
        compile_commands: None,
        too_large: 0,
        walk_errors: 0,
    };

    let mut builder = WalkBuilder::new(root);
    builder.follow_links(false);
    if !settings.respect_gitignore {
        builder
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .ignore(false)
            .parents(false);
    }

    for result in builder.build() {
        let Ok(entry) = result else {
            output.walk_errors += 1;
            continue;
        };
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        match path.file_name().and_then(|n| n.to_str()) {
            Some(CARGO_MANIFEST) => {
                output.manifests.push(path.to_path_buf());
                continue;
            }
            Some(COMPILE_COMMANDS) => {
                if output.compile_commands.is_none() {
                    output.compile_commands = Some(path.to_path_buf());
                }
                continue;
            }
            _ => {}
        }
        let Some(classification) = classify(path, settings.header_policy) else {
            continue;
        };
        if !settings.selection.includes(classification.language) {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            output.walk_errors += 1;
            continue;
        };
        let byte_len = metadata.len();
        if byte_len > settings.max_file_bytes {
            output.too_large += 1;
            continue;
        }
        let relative_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();
        output.candidates.push(Candidate {
            relative_path,
            absolute_path: path.to_path_buf(),
            classification,
            byte_len,
        });
    }

    output
}
