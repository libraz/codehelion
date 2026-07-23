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

mod build_variant;
mod cargo;
mod compile_commands;
mod generated;
mod language;
mod source_unit;
mod walk;

pub use build_variant::{AnalysisMode, BuildVariant, NORMALIZATION_VERSION};
pub use cargo::{CargoLayout, PackageInfo};
pub use compile_commands::{CompileCommands, CompileCommandsError, CompileEntry};
pub use generated::{DEFAULT_MARKERS, DEFAULT_SCAN_LINES, GeneratedMarkers};
pub use language::{Classification, HeaderPolicy, Language, LanguageSelection};
pub use source_unit::{ContentHash, SourceUnit, TargetKind};

use std::path::{Path, PathBuf};

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
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            respect_gitignore: true,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            header_policy: HeaderPolicy::default(),
            languages: LanguageSelection::default(),
            generated_markers: GeneratedMarkers::default(),
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
    /// Directory entries the walker could not read.
    pub walk_errors: u64,
}

impl SkipReport {
    /// Total number of skipped entries.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.too_large + self.binary + self.unreadable + self.walk_errors
    }
}

/// The outcome of a discovery run.
#[derive(Debug, Clone)]
pub struct DiscoveryReport {
    /// Source units selected for analysis, ordered by relative path.
    pub units: Vec<SourceUnit>,
    /// The implicit build variant every unit is attributed to.
    pub build_variant: BuildVariant,
    /// Cargo packages recognised in the tree, ordered by name.
    pub packages: Vec<PackageInfo>,
    /// Relative paths excluded because they are generated, ordered by path.
    pub suppressed_generated: Vec<PathBuf>,
    /// Counts of files skipped for other reasons.
    pub skipped: SkipReport,
    /// Parsed compilation database, if one was found and read successfully.
    pub compile_commands: Option<CompileCommands>,
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
pub fn discover(root: &Path, config: &DiscoveryConfig) -> Result<DiscoveryReport, DiscoveryError> {
    let root = root.canonicalize().map_err(|source| DiscoveryError::Root {
        path: root.to_path_buf(),
        source,
    })?;

    let settings = WalkSettings {
        respect_gitignore: config.respect_gitignore,
        max_file_bytes: config.max_file_bytes,
        header_policy: config.header_policy,
        selection: config.languages,
    };
    let walked = walk::collect(&root, &settings);
    let layout = CargoLayout::from_manifests(&walked.manifests);
    let compile_commands = walked
        .compile_commands
        .as_deref()
        .and_then(|path| CompileCommands::read(path).ok());

    let mut skipped = SkipReport {
        too_large: walked.too_large,
        walk_errors: walked.walk_errors,
        ..SkipReport::default()
    };
    let mut units = Vec::new();
    let mut suppressed_generated = Vec::new();

    for candidate in walked.candidates {
        let Ok(bytes) = std::fs::read(&candidate.absolute_path) else {
            skipped.unreadable += 1;
            continue;
        };
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
        units.push(SourceUnit {
            relative_path: candidate.relative_path,
            absolute_path: candidate.absolute_path,
            language: candidate.classification.language,
            is_header: candidate.classification.is_header,
            content_hash,
            byte_len: candidate.byte_len,
            package,
            target_kind,
        });
    }

    units.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    suppressed_generated.sort();

    Ok(DiscoveryReport {
        units,
        build_variant: BuildVariant::fast(config.languages),
        packages: layout.packages(),
        suppressed_generated,
        skipped,
        compile_commands,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
