//! Project discovery: turning a directory tree into the set of source units the
//! Fast source-audit engine will analyse.
//!
//! Discovery is filesystem-only. It reads source files, Cargo manifests and, if
//! present, a `compile_commands.json`; it never executes build scripts,
//! procedural macros or any target code. It is also where files are
//! pre-suppressed: generated files, binary files and files over the size
//! ceiling are excluded before any clone candidate is generated, and every
//! excluded file is accounted for so nothing is dropped silently. Each result
//! is attributed to a single implicit [`BuildVariant`], so results from
//! different variants are never conflated.

mod build_config;
mod build_variant;
mod cargo;
mod compile_commands;
mod generated;
mod language;
mod source_unit;
mod walk;

pub use build_config::{
    BuildConfiguration, CppBuild, EXCLUDED, EXCLUDED_WITH_VALUE, RustBuild, Setting, Shape,
    content_hash,
};
pub use build_variant::{AnalysisMode, BuildVariant, NORMALIZATION_VERSION, Partition, partition};
pub use cargo::{CargoLayout, PackageInfo};
pub use compile_commands::{CompileCommands, CompileCommandsError, CompileEntry};
pub use generated::{DEFAULT_MARKERS, DEFAULT_SCAN_LINES, GeneratedMarkers};
pub use language::{Classification, HeaderEvidence, HeaderPolicy, Language, LanguageSelection};
pub use source_unit::{ContentHash, SourceUnit, TargetKind};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use self::walk::WalkSettings;

/// Default per-file size ceiling, in bytes.
///
/// Files larger than this are skipped: they are almost always generated tables
/// or vendored blobs, and pairing every fragment of a multi-megabyte file
/// dominates the candidate budget.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// Bytes of a file's head inspected for the binary check and generated markers.
const HEAD_BYTES: usize = 8 * 1024;

/// Settings that control a discovery run.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Honour `.gitignore` and related ignore files (default `true`).
    pub respect_gitignore: bool,
    /// Per-file size ceiling in bytes.
    pub max_file_bytes: u64,
    /// How to classify bare `.h` headers.
    pub header_policy: HeaderPolicy,
    /// Languages to enumerate.
    pub languages: LanguageSelection,
    /// Markers that flag a file as generated.
    pub generated_markers: GeneratedMarkers,
    /// Compilation database to use instead of an automatically discovered
    /// `compile_commands.json`.
    pub compile_commands: Option<PathBuf>,
    /// Whether the source walker follows symbolic links.
    pub follow_links: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            respect_gitignore: true,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            header_policy: HeaderPolicy::default(),
            languages: LanguageSelection::default(),
            generated_markers: GeneratedMarkers::default(),
            compile_commands: None,
            follow_links: false,
        }
    }
}

/// Counts of files excluded for reasons other than being generated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SkipReport {
    /// Files past the size ceiling.
    pub too_large: u64,
    /// Files that looked binary (a NUL byte in their head).
    pub binary: u64,
    /// Files that could not be read.
    pub unreadable: u64,
    /// Source files excluded because their language was disabled.
    pub language_excluded: u64,
    /// Symbolic links deliberately left unresolved by the walker.
    pub symlinks: u64,
    /// Symbolic-link files deliberately left unresolved by the walker.
    pub symlink_files: u64,
    /// Symbolic-link directories deliberately left unresolved by the walker.
    pub symlink_directories: u64,
    /// Directory entries the walker could not read.
    pub walk_errors: u64,
}

impl SkipReport {
    /// Total number of skipped entries.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.too_large
            + self.binary
            + self.unreadable
            + self.language_excluded
            + self.symlinks
            + self.walk_errors
    }
}

/// The outcome of a discovery run.
#[derive(Debug, Clone)]
pub struct DiscoveryReport {
    /// Source units selected for analysis, ordered by relative path.
    pub units: Vec<SourceUnit>,
    /// The implicit build variant every unit is attributed to.
    pub build_variant: BuildVariant,
    /// The language bare `.h` headers were read as: what the configured
    /// [`HeaderPolicy`] named, or what the tree pointed to when the policy
    /// left it to detection.
    pub header_language: Language,
    /// Cargo packages recognised in the tree, ordered by name.
    pub packages: Vec<PackageInfo>,
    /// Relative paths excluded because they are generated, ordered by path.
    pub suppressed_generated: Vec<PathBuf>,
    /// Counts of files skipped for other reasons.
    pub skipped: SkipReport,
    /// Parsed compilation database, if one was found and read successfully.
    pub compile_commands: Option<CompileCommands>,
    /// A compilation database found during discovery but not usable for
    /// semantic analysis.
    pub compile_commands_error: Option<CompileCommandsDiagnostic>,
}

/// A compilation database that discovery found but could not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileCommandsDiagnostic {
    /// The database path selected during discovery.
    pub path: PathBuf,
    /// The user-facing reason the database could not be used.
    pub message: String,
}

/// A failure that prevents discovery from running at all.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// The scan root does not exist or could not be resolved.
    #[error("resolving scan root {path}: {source}")]
    Root {
        /// The path that could not be resolved.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Discover the source units under `root`.
///
/// The tree is traversed once. Generated, binary and oversized files are
/// excluded and accounted for; the returned [`DiscoveryReport`] lists the
/// selected units in a deterministic order.
///
/// # Errors
///
/// Returns [`DiscoveryError`] if `root` cannot be resolved to a directory.
#[allow(
    clippy::too_many_lines,
    reason = "discovery keeps traversal accounting and the single-read source handoff together"
)]
pub fn discover(root: &Path, config: &DiscoveryConfig) -> Result<DiscoveryReport, DiscoveryError> {
    let root = crate::paths::canonical(root).map_err(|source| DiscoveryError::Root {
        path: root.to_path_buf(),
        source,
    })?;

    let settings = WalkSettings {
        respect_gitignore: config.respect_gitignore,
        max_file_bytes: config.max_file_bytes,
        header_policy: config.header_policy,
        selection: config.languages,
        follow_links: config.follow_links,
    };
    let walked = walk::collect(&root, &settings);
    let mut skipped = SkipReport {
        too_large: walked.too_large,
        language_excluded: walked.language_excluded,
        symlinks: walked.symlinks,
        symlink_files: walked.symlink_files,
        symlink_directories: walked.symlink_directories,
        walk_errors: walked.walk_errors,
        ..SkipReport::default()
    };
    let header_evidence = walked.evidence.verdict();
    let manifests = walked.manifests;
    let compile_candidates = walked.compile_commands;
    // Settle the bare `.h` headers before anything reads them: the grammar a
    // header is parsed with is part of the build variant, so it is one
    // decision for the whole run rather than a per-file guess. An explicit
    // policy is the answer where there is one; detection only fills the gap.
    let mut loaded = Vec::new();
    for candidate in walked.candidates {
        match std::fs::read(&candidate.absolute_path) {
            Ok(bytes) => loaded.push((candidate, bytes)),
            Err(_) => skipped.unreadable += 1,
        }
    }
    let header_language = match config.header_policy {
        HeaderPolicy::C => Language::C,
        HeaderPolicy::Cpp => Language::Cpp,
        HeaderPolicy::Detect => header_evidence.unwrap_or_else(|| headers_read_alone(&loaded)),
    };
    let layout = CargoLayout::from_manifests(&manifests);
    let compile_commands_path = config.compile_commands.as_ref().map_or_else(
        || select_compile_commands(&root, compile_candidates),
        |path| Some(resolve_compile_commands_path(&root, path)),
    );
    let (compile_commands, compile_commands_error) = compile_commands_path.map_or_else(
        || (None, None),
        |path| match CompileCommands::read_with_limit(&path, config.max_file_bytes) {
            Ok(database) => (Some(database), None),
            Err(error) => (
                None,
                Some(CompileCommandsDiagnostic {
                    path,
                    message: error.to_string(),
                }),
            ),
        },
    );

    let mut units = Vec::new();
    let mut suppressed_generated = Vec::new();

    for (candidate, bytes) in loaded {
        let classification = candidate.classification.settled(header_language);
        // The walk let a header through while either C or C++ was enabled,
        // because it did not yet know which one it was.
        if !config.languages.includes(classification.language) {
            skipped.language_excluded += 1;
            continue;
        }
        let head = &bytes[..bytes.len().min(HEAD_BYTES)];
        if head.contains(&0) {
            skipped.binary += 1;
            continue;
        }
        if config
            .generated_markers
            .is_generated(&String::from_utf8_lossy(head))
        {
            suppressed_generated.push(candidate.relative_path);
            continue;
        }
        let content_hash = ContentHash::of(&bytes);
        let (package, target_kind) = layout.classify(&candidate.absolute_path);
        let crate_name = layout.crate_name(&candidate.absolute_path);
        units.push(SourceUnit {
            relative_path: candidate.relative_path,
            absolute_path: candidate.absolute_path,
            language: classification.language,
            is_header: classification.is_header,
            content_hash,
            byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            source_bytes: Arc::from(bytes),
            package,
            crate_name,
            target_kind,
        });
    }

    units.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    suppressed_generated.sort();

    Ok(DiscoveryReport {
        units,
        build_variant: BuildVariant::fast(config.languages, header_language),
        header_language,
        packages: layout.packages(),
        suppressed_generated,
        skipped,
        compile_commands,
        compile_commands_error,
    })
}

fn resolve_compile_commands_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn select_compile_commands(root: &Path, mut candidates: Vec<PathBuf>) -> Option<PathBuf> {
    candidates.sort_by(|left, right| {
        compile_commands_depth(root, left)
            .cmp(&compile_commands_depth(root, right))
            .then_with(|| left.cmp(right))
    });
    candidates.into_iter().next()
}

fn compile_commands_depth(root: &Path, path: &Path) -> usize {
    path.strip_prefix(root)
        .map_or(usize::MAX, |relative| relative.components().count())
}

/// Settle bare `.h` headers from the headers themselves, for a tree that has
/// nothing else to settle them from.
///
/// Reached only when no `.c`, `.cpp` or unambiguously-extended header was
/// found at all, which in practice means a header-only library: every line the
/// run will read is in these files, so the grammar is the whole result rather
/// than a detail of it. Each header is read for a C++-only spelling and the
/// first one that speaks decides — `language::speaks_cpp` says why one is
/// enough, and why C is the answer when none of them says otherwise.
fn headers_read_alone(candidates: &[(walk::Candidate, Vec<u8>)]) -> Language {
    for (candidate, bytes) in candidates {
        if !candidate.classification.provisional {
            continue;
        }
        if language::speaks_cpp(&String::from_utf8_lossy(bytes)) {
            return Language::Cpp;
        }
    }
    Language::C
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a small tree and return its root. The temp dir is returned too so
    /// the caller keeps it alive for the duration of the test.
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"demo\"\n").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        (dir, root)
    }

    #[test]
    fn enumerates_sources_with_package_and_target_attribution() {
        let (_guard, root) = fixture();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.units.len(), 2);
        assert_eq!(report.packages.len(), 1);
        assert_eq!(report.packages[0].name, "demo");

        let lib = report
            .units
            .iter()
            .find(|u| u.relative_path == Path::new("src/lib.rs"))
            .unwrap();
        assert_eq!(lib.language, Language::Rust);
        assert_eq!(lib.package.as_deref(), Some("demo"));
        assert_eq!(lib.target_kind, TargetKind::Library);

        let main = report
            .units
            .iter()
            .find(|u| u.relative_path == Path::new("src/main.rs"))
            .unwrap();
        assert_eq!(main.target_kind, TargetKind::Binary);
    }

    #[test]
    fn source_bytes_are_the_bytes_the_discovery_hash_describes() {
        let (_guard, root) = fixture();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        for unit in &report.units {
            assert_eq!(unit.content_hash, ContentHash::of(&unit.source_bytes));
        }
    }

    /// Discovery is where the package layout is read, so it is where a file
    /// learns the crate a compiler would be asked about. The package name and
    /// the crate name are spelled differently here, so a unit that carried the
    /// package instead would fail rather than pass by looking alike.
    #[test]
    fn a_unit_carries_the_crate_a_compiler_knows_it_by() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        fs::write(root.join("Cargo.toml"), "[package]\nname = \"my-demo\"\n").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn a() {}\n").unwrap();

        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        let lib = &report.units[0];
        assert_eq!(lib.package.as_deref(), Some("my-demo"));
        assert_eq!(lib.crate_name.as_deref(), Some("my_demo"));
    }

    #[test]
    fn units_are_ordered_by_relative_path() {
        let (_guard, root) = fixture();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        let paths: Vec<_> = report.units.iter().map(|u| &u.relative_path).collect();
        let mut sorted = paths.clone();
        sorted.sort();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn generated_files_are_suppressed_and_counted_not_dropped() {
        let (_guard, root) = fixture();
        fs::write(root.join("src/gen.rs"), "// @generated\npub fn g() {}\n").unwrap();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert!(
            report
                .units
                .iter()
                .all(|u| u.relative_path != Path::new("src/gen.rs"))
        );
        assert_eq!(
            report.suppressed_generated,
            vec![PathBuf::from("src/gen.rs")]
        );
    }

    /// The binding generators are what makes a foreign-function crate mostly
    /// machine output, and none of them writes the banner the code generators
    /// settled on. A tree of bindings that reaches the units is a tree whose
    /// whole report is about the generator.
    #[test]
    fn bindings_are_suppressed_though_their_banner_follows_no_convention() {
        let (_guard, root) = fixture();
        fs::write(
            root.join("src/bindings.rs"),
            "/* automatically generated by rust-bindgen 0.72.1 */\npub fn b() {}\n",
        )
        .unwrap();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(
            report.suppressed_generated,
            vec![PathBuf::from("src/bindings.rs")]
        );
    }

    #[test]
    fn binary_files_are_skipped() {
        let (_guard, root) = fixture();
        fs::write(root.join("src/blob.rs"), [0u8, 1, 2, 3, 0]).unwrap();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.skipped.binary, 1);
        assert!(
            report
                .units
                .iter()
                .all(|u| u.relative_path != Path::new("src/blob.rs"))
        );
    }

    #[test]
    fn oversized_files_are_skipped() {
        let (_guard, root) = fixture();
        fs::write(root.join("src/big.rs"), vec![b'x'; 4096]).unwrap();
        let config = DiscoveryConfig {
            max_file_bytes: 1024,
            ..DiscoveryConfig::default()
        };
        let report = discover(&root, &config).unwrap();
        assert_eq!(report.skipped.too_large, 1);
    }

    #[test]
    fn oversized_metadata_inputs_are_skipped_before_they_are_read() {
        let (_guard, root) = fixture();
        fs::write(root.join("Cargo.toml"), "x".repeat(4096)).unwrap();
        fs::write(root.join("compile_commands.json"), "[{}]".repeat(1024)).unwrap();
        let config = DiscoveryConfig {
            max_file_bytes: 1024,
            ..DiscoveryConfig::default()
        };

        let report = discover(&root, &config).unwrap();

        assert!(report.packages.is_empty());
        assert!(report.compile_commands.is_none());
        assert!(report.compile_commands_error.is_none());
        assert_eq!(report.skipped.too_large, 2);
    }

    #[test]
    fn an_oversized_explicit_compilation_database_is_reported_without_reading_it() {
        let (_guard, root) = fixture();
        let database = root.join("commands.json");
        fs::write(&database, "[{}]".repeat(1024)).unwrap();
        let config = DiscoveryConfig {
            max_file_bytes: 1024,
            compile_commands: Some(PathBuf::from("commands.json")),
            ..DiscoveryConfig::default()
        };

        let report = discover(&root, &config).unwrap();

        assert!(report.compile_commands.is_none());
        assert_eq!(report.skipped.too_large, 1);
        assert_eq!(
            report
                .compile_commands_error
                .as_ref()
                .map(|diagnostic| diagnostic.message.as_str()),
            Some("compile_commands.json is 4096 bytes, exceeding the 1024-byte limit")
        );
    }

    /// `CMake` commonly leaves its database in an ignored build directory and
    /// exposes it through this root-level symlink for editor tooling.
    #[cfg(unix)]
    #[test]
    fn discovers_a_root_compilation_database_symlink_into_an_ignored_build_directory() {
        let (_guard, root) = fixture();
        let build = root.join("build");
        fs::create_dir_all(&build).unwrap();
        fs::write(root.join(".gitignore"), "build/\n").unwrap();
        fs::write(
            build.join("compile_commands.json"),
            r#"[{"directory":"/work","file":"/work/src/main.cpp","arguments":["clang++","-c","/work/src/main.cpp"]}]"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "build/compile_commands.json",
            root.join("compile_commands.json"),
        )
        .unwrap();

        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(
            report.compile_commands.as_ref().map(|db| db.entries.len()),
            Some(1)
        );
    }

    #[test]
    fn an_explicit_compilation_database_overrides_automatic_discovery() {
        let (_guard, root) = fixture();
        fs::write(
            root.join("compile_commands.json"),
            r#"[{"directory":"/work","file":"/work/automatic.cpp"}]"#,
        )
        .unwrap();
        let explicit = root.join("build/commands.json");
        fs::create_dir_all(explicit.parent().unwrap()).unwrap();
        fs::write(
            &explicit,
            r#"[{"directory":"/work","file":"/work/explicit.cpp"}]"#,
        )
        .unwrap();
        let config = DiscoveryConfig {
            compile_commands: Some(PathBuf::from("build/commands.json")),
            ..DiscoveryConfig::default()
        };

        let report = discover(&root, &config).unwrap();
        assert_eq!(
            report
                .compile_commands
                .as_ref()
                .and_then(|db| db.entries.first())
                .map(|entry| entry.file.as_path()),
            Some(Path::new("/work/explicit.cpp"))
        );
    }

    #[test]
    fn automatic_compilation_database_selection_is_shallow_then_lexical() {
        let root = Path::new("/work");
        let selected = select_compile_commands(
            root,
            vec![
                root.join("z/compile_commands.json"),
                root.join("a/compile_commands.json"),
                root.join("nested/a/compile_commands.json"),
            ],
        );
        assert_eq!(selected, Some(root.join("a/compile_commands.json")));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_counted_without_reading_or_following_them() {
        use std::os::unix::fs::symlink;

        let (_guard, root) = fixture();
        let target = root.join("src/lib.rs");
        symlink(&target, root.join("src/linked.rs")).unwrap();

        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.skipped.symlinks, 1);
        assert_eq!(report.skipped.symlink_files, 1);
        assert_eq!(report.skipped.symlink_directories, 0);
        assert_eq!(report.skipped.total(), 1);
        assert!(
            report
                .units
                .iter()
                .all(|unit| unit.relative_path != Path::new("src/linked.rs"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn untracked_link_directories_are_counted_separately_from_linked_files() {
        use std::os::unix::fs::symlink;

        let (_guard, root) = fixture();
        symlink(root.join("src"), root.join("linked-src")).unwrap();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.skipped.symlinks, 1);
        assert_eq!(report.skipped.symlink_files, 0);
        assert_eq!(report.skipped.symlink_directories, 1);
    }

    #[cfg(unix)]
    #[test]
    fn every_walked_source_is_accounted_for_by_one_discovery_outcome() {
        use std::os::unix::fs::symlink;

        let (_guard, root) = fixture();
        fs::write(root.join("src/util.c"), "int value(void) { return 1; }\n").unwrap();
        fs::write(
            root.join("src/generated.rs"),
            "// @generated\nfn generated() {}\n",
        )
        .unwrap();
        fs::write(root.join("src/binary.rs"), b"fn binary() {}\0").unwrap();
        symlink(root.join("src/lib.rs"), root.join("src/linked.rs")).unwrap();
        let report = discover(
            &root,
            &DiscoveryConfig {
                languages: LanguageSelection {
                    rust: true,
                    c: false,
                    cpp: false,
                },
                ..DiscoveryConfig::default()
            },
        )
        .unwrap();
        let accounted = report.units.len()
            + report.suppressed_generated.len()
            + usize::try_from(
                report.skipped.language_excluded + report.skipped.binary + report.skipped.symlinks,
            )
            .unwrap();
        assert_eq!(accounted, 6, "every walked source reached one outcome");
    }

    #[cfg(unix)]
    #[test]
    fn following_links_includes_a_linked_source_without_losing_the_target() {
        use std::os::unix::fs::symlink;

        let (_guard, root) = fixture();
        let target = root.join("src/lib.rs");
        symlink(&target, root.join("src/linked.rs")).unwrap();
        let report = discover(
            &root,
            &DiscoveryConfig {
                follow_links: true,
                ..DiscoveryConfig::default()
            },
        )
        .unwrap();
        let paths: Vec<_> = report
            .units
            .iter()
            .map(|unit| unit.relative_path.as_path())
            .collect();
        assert!(paths.contains(&Path::new("src/lib.rs")));
        assert!(paths.contains(&Path::new("src/linked.rs")));
        assert_eq!(report.skipped.symlinks, 0);
    }

    #[cfg(unix)]
    #[test]
    fn following_a_directory_cycle_terminates_and_accounts_for_the_walk_error() {
        use std::os::unix::fs::symlink;

        let (_guard, root) = fixture();
        symlink(&root, root.join("src/cycle")).unwrap();
        let report = discover(
            &root,
            &DiscoveryConfig {
                follow_links: true,
                ..DiscoveryConfig::default()
            },
        )
        .unwrap();
        assert!(
            report.skipped.walk_errors > 0,
            "the walker must report a detected symlink cycle"
        );
        assert!(
            report
                .units
                .iter()
                .any(|unit| unit.relative_path == Path::new("src/lib.rs"))
        );
    }

    #[test]
    fn no_ignore_includes_dot_paths() {
        let (_guard, root) = fixture();
        fs::create_dir_all(root.join(".generated")).unwrap();
        fs::write(root.join(".generated/extra.rs"), "pub fn extra() {}\n").unwrap();

        let default = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert!(
            default
                .units
                .iter()
                .all(|unit| unit.relative_path != Path::new(".generated/extra.rs"))
        );

        let report = discover(
            &root,
            &DiscoveryConfig {
                respect_gitignore: false,
                ..DiscoveryConfig::default()
            },
        )
        .unwrap();
        assert!(
            report
                .units
                .iter()
                .any(|unit| unit.relative_path == Path::new(".generated/extra.rs"))
        );
    }

    #[test]
    fn language_selection_excludes_disabled_languages() {
        let (_guard, root) = fixture();
        fs::write(root.join("src/util.c"), "int a(void){return 0;}\n").unwrap();
        let config = DiscoveryConfig {
            languages: LanguageSelection {
                rust: true,
                c: false,
                cpp: false,
            },
            ..DiscoveryConfig::default()
        };
        let report = discover(&root, &config).unwrap();
        assert!(report.units.iter().all(|u| u.language == Language::Rust));
        assert_eq!(report.skipped.language_excluded, 1);
    }

    /// A tree holding `names`, each an empty-but-valid source file.
    fn tree_of(names: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        for name in names {
            fs::write(root.join(name), "int a(void){return 0;}\n").unwrap();
        }
        (dir, root)
    }

    /// The language discovery settled on for `name` in a tree of `names`.
    fn language_of(names: &[&str], name: &str) -> Language {
        let (_guard, root) = tree_of(names);
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        report
            .units
            .iter()
            .find(|unit| unit.relative_path == Path::new(name))
            .unwrap_or_else(|| panic!("{name} was not discovered"))
            .language
    }

    #[test]
    fn a_bare_header_follows_the_language_the_tree_is_written_in() {
        assert_eq!(
            language_of(&["a.cpp", "b.cpp", "x.h"], "x.h"),
            Language::Cpp
        );
        assert_eq!(language_of(&["a.c", "b.c", "x.h"], "x.h"), Language::C);
    }

    #[test]
    fn a_cpp_only_spelling_after_a_long_header_preamble_settles_the_dialect() {
        let (_guard, root) = tree_of(&["only.h"]);
        let preamble = "license line\n".repeat(HEAD_BYTES);
        fs::write(
            root.join("only.h"),
            format!("/* {preamble} */\nnamespace audit {{ struct Entry {{}}; }}\n"),
        )
        .unwrap();

        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.header_language, Language::Cpp);
        assert_eq!(report.build_variant.headers, Some(Language::Cpp));
    }

    #[test]
    fn the_settled_header_language_is_reported_and_carried_by_the_variant() {
        let (_guard, root) = tree_of(&["a.cpp", "x.h"]);
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.header_language, Language::Cpp);
        assert_eq!(report.build_variant.headers, Some(Language::Cpp));
    }

    #[test]
    fn an_explicit_header_policy_overrides_what_the_tree_suggests() {
        let (_guard, root) = tree_of(&["a.cpp", "b.cpp", "x.h"]);
        let config = DiscoveryConfig {
            header_policy: HeaderPolicy::C,
            ..DiscoveryConfig::default()
        };
        let report = discover(&root, &config).unwrap();
        let header = report
            .units
            .iter()
            .find(|unit| unit.relative_path == Path::new("x.h"))
            .unwrap();
        assert_eq!(
            header.language,
            Language::C,
            "the policy decided, not the tree"
        );
        // What the run reports and attributes its results to is the grammar it
        // used, not the one it would have chosen unaided.
        assert_eq!(report.header_language, Language::C);
        assert_eq!(report.build_variant.headers, Some(Language::C));
    }

    #[test]
    fn a_header_settled_into_a_disabled_language_is_left_out() {
        // The walk keeps a `.h` while either C or C++ is enabled, because it
        // does not yet know which it is. Once settled, the selection applies.
        let (_guard, root) = tree_of(&["a.cpp", "b.cpp", "x.h", "plain.c"]);
        let config = DiscoveryConfig {
            languages: LanguageSelection {
                rust: true,
                c: true,
                cpp: false,
            },
            ..DiscoveryConfig::default()
        };
        let report = discover(&root, &config).unwrap();
        let paths: Vec<&Path> = report
            .units
            .iter()
            .map(|unit| unit.relative_path.as_path())
            .collect();
        assert_eq!(
            paths,
            vec![Path::new("plain.c")],
            "the header settled on C++, which this run does not analyse"
        );
        assert_eq!(report.skipped.language_excluded, 3);
    }

    #[test]
    fn every_unit_shares_the_fast_build_variant() {
        let (_guard, root) = fixture();
        let report = discover(&root, &DiscoveryConfig::default()).unwrap();
        assert_eq!(report.build_variant.mode, AnalysisMode::Fast);
        assert_eq!(
            report.build_variant.normalization_version,
            NORMALIZATION_VERSION
        );
    }

    #[test]
    fn missing_root_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        assert!(matches!(
            discover(&missing, &DiscoveryConfig::default()),
            Err(DiscoveryError::Root { .. })
        ));
    }
}
