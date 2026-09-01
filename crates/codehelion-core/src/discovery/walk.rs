//! Filesystem traversal that produces classified source-file candidates.
//!
//! The walk is read-only. A file it recognises by name — a Cargo manifest or a
//! compilation database — is classified by the role it plays before any of the
//! filters that apply to source candidates, because those filters exist to
//! bound the cost of code to compare and say nothing about metadata: a project
//! that exposes its database through a symbolic link, or one whose database is
//! larger than a source file may be, still gets the build settings it wrote
//! down or a reason it did not.
//!
//! Everything else is a source candidate, filtered by a byte-size ceiling and,
//! unless `follow_links` says otherwise, by leaving symbolic links unresolved:
//! a link is counted rather than walked, and the target it names is discovered
//! on its own if it is in the tree at all. Files excluded either way are
//! counted, not silently dropped.
//!
//! `.gitignore` and related ignore files are honoured by default whether or
//! not the tree sits in a git worktree, so an unpacked archive or a partial
//! checkout is enumerated exactly as the repository it came from would be.

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use super::language::{
    Classification, HeaderEvidence, HeaderPolicy, Language, LanguageSelection, classify,
};

const CARGO_MANIFEST: &str = "Cargo.toml";
const COMPILE_COMMANDS: &str = "compile_commands.json";

/// A file discovery recognises by name rather than by its contents.
#[derive(Clone, Copy)]
enum MetadataKind {
    /// A Cargo manifest, read for the package layout.
    Manifest,
    /// A Clang compilation database, read for the build settings.
    CompileCommands,
}

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
    /// Source candidates skipped because they exceeded the size ceiling.
    pub(super) too_large: u64,
    /// Recognised metadata files that exceeded the size ceiling.
    pub(super) oversized_metadata: u64,
    /// Source files excluded because their language was disabled.
    pub(super) language_excluded: u64,
    /// Paths that name a source file but are not regular files: FIFOs,
    /// sockets, device nodes.
    pub(super) special_files: u64,
    /// Symbolic links deliberately left unresolved by the walker.
    pub(super) symlinks: u64,
    /// Symbolic links that name a file.
    pub(super) symlink_files: u64,
    /// Symbolic links that name a directory.
    pub(super) symlink_directories: u64,
    /// Symbolic links whose own entry could not be read, so they name neither.
    pub(super) symlink_unresolved: u64,
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
        oversized_metadata: 0,
        language_excluded: 0,
        special_files: 0,
        symlinks: 0,
        symlink_files: 0,
        symlink_directories: 0,
        symlink_unresolved: 0,
        walk_errors: 0,
    };

    let mut builder = WalkBuilder::new(root);
    builder.follow_links(settings.follow_links);
    if settings.respect_gitignore {
        // An ignore file states what the project generates, and it states it
        // whether or not the copy being scanned kept the repository around. A
        // tree unpacked from an archive or checked out without its history has
        // the same `build/` and `target/` in it as the worktree it came from,
        // and enumerating those is indistinguishable from being asked not to
        // honour the ignore rules at all.
        builder.require_git(false);
    } else {
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
        let path = entry.path();
        if let Some((kind, byte_len)) = recognised_metadata(path) {
            if byte_len > settings.max_file_bytes {
                output.oversized_metadata += 1;
            }
            match kind {
                // The database reader enforces the ceiling itself and names
                // what it rejected, so an oversized database is handed on
                // rather than dropped here: reporting the database the run
                // would have used is the difference between a scan that has no
                // build settings and one that says why.
                MetadataKind::CompileCommands => output.compile_commands.push(path.to_path_buf()),
                // A manifest has no such channel and is read whole, so the
                // ceiling applies to it here and the count above is all the
                // report has to say about it.
                MetadataKind::Manifest => {
                    if byte_len <= settings.max_file_bytes {
                        output.manifests.push(path.to_path_buf());
                    }
                }
            }
            continue;
        }
        if !settings.follow_links
            && entry
                .file_type()
                .is_some_and(|file_type| file_type.is_symlink())
        {
            output.symlinks += 1;
            match std::fs::metadata(path) {
                Ok(metadata) if metadata.is_dir() => output.symlink_directories += 1,
                Ok(_) => output.symlink_files += 1,
                // A link naming nothing that can be reached is neither, and
                // calling it a file would report a source file that is not
                // there.
                Err(_) => output.symlink_unresolved += 1,
            }
            continue;
        }
        match entry.file_type() {
            Some(file_type) if file_type.is_file() => {}
            // A directory is the traversal itself, not an entry the walk
            // decides anything about.
            Some(file_type) if file_type.is_dir() => continue,
            // A FIFO, socket or device node named like a source file is not a
            // file the run can read — opening one is what the walk must not do,
            // and it holds a source path that reaches no comparison. It is
            // counted where an unreadable path is counted, apart from the
            // directory-traversal errors above, rather than dropped: an entry
            // that reaches no outcome at all is one the report cannot mention.
            _ => {
                // Only a path the run would have compared is worth a count;
                // a special file with an extension nothing reads is as
                // uninteresting as a regular file with one.
                if classify(path, settings.header_policy).is_some() {
                    output.special_files += 1;
                }
                continue;
            }
        }
        let Ok(metadata) = entry.metadata() else {
            output.walk_errors += 1;
            continue;
        };
        if metadata.len() > settings.max_file_bytes {
            output.too_large += 1;
            continue;
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

/// The kind and byte length of a metadata file discovery recognises at `path`.
///
/// A symbolic link is resolved: a compilation database left in an ignored
/// build directory and exposed at the project root through a link is the file
/// the project means, and refusing to look through the link would leave the
/// run without any of the build settings that database records. `None` for
/// anything the resolved path is not a readable regular file for, which the
/// general classification below then accounts for as what it is.
fn recognised_metadata(path: &Path) -> Option<(MetadataKind, u64)> {
    let kind = match path.file_name().and_then(|name| name.to_str()) {
        Some(CARGO_MANIFEST) => MetadataKind::Manifest,
        Some(COMPILE_COMMANDS) => MetadataKind::CompileCommands,
        _ => return None,
    };
    let metadata = std::fs::metadata(path).ok()?;
    metadata.is_file().then_some((kind, metadata.len()))
}
