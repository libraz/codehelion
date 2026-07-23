//! Read-only recognition of Cargo package layout.
//!
//! Cargo manifests are parsed as plain TOML to attribute each source file to a
//! package and target kind. Nothing here runs `cargo`, build scripts or
//! procedural macros: a manifest is data, read and discarded. Package
//! membership uses the nearest enclosing manifest with a `[package]` section, so
//! workspaces are handled without resolving member globs.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::source_unit::TargetKind;

#[derive(Debug, Deserialize)]
struct Manifest {
    package: Option<PackageSection>,
    lib: Option<TargetSection>,
    #[serde(default)]
    bin: Vec<TargetSection>,
}

#[derive(Debug, Deserialize)]
struct PackageSection {
    name: String,
}

#[derive(Debug, Deserialize)]
struct TargetSection {
    path: Option<String>,
}

/// One Cargo package, rooted at the directory holding its manifest.
#[derive(Debug, Clone)]
struct Package {
    root: PathBuf,
    name: String,
    /// Absolute path of an explicit `[lib] path`, if the manifest set one.
    lib_path: Option<PathBuf>,
    /// Absolute paths of explicit `[[bin]] path` entries.
    bin_paths: Vec<PathBuf>,
}

/// The recognised Cargo packages in a scanned tree.
#[derive(Debug, Clone, Default)]
pub struct CargoLayout {
    /// Packages sorted by descending root-path depth, so the first ancestor
    /// match is the nearest enclosing package.
    packages: Vec<Package>,
}

/// A package discovered in the tree, for reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    /// Package name from the manifest.
    pub name: String,
    /// Package root directory.
    pub root: PathBuf,
}

impl CargoLayout {
    /// Build a layout from a set of `Cargo.toml` paths.
    ///
    /// Manifests without a `[package]` section (pure `[workspace]` roots) or
    /// that fail to parse are skipped; a malformed manifest never aborts
    /// discovery.
    #[must_use]
    pub fn from_manifests(manifests: &[PathBuf]) -> Self {
        let mut packages = Vec::new();
        for manifest_path in manifests {
            let Some(root) = manifest_path.parent() else {
                continue;
            };
            let Ok(text) = std::fs::read_to_string(manifest_path) else {
                continue;
            };
            let Ok(manifest) = toml::from_str::<Manifest>(&text) else {
                continue;
            };
            let Some(package) = manifest.package else {
                continue;
            };
            let lib_path = manifest
                .lib
                .and_then(|lib| lib.path)
                .map(|path| root.join(path));
            let bin_paths = manifest
                .bin
                .into_iter()
                .filter_map(|bin| bin.path)
                .map(|path| root.join(path))
                .collect();
            packages.push(Package {
                root: root.to_path_buf(),
                name: package.name,
                lib_path,
                bin_paths,
            });
        }
        // Deeper roots first: a nested package wins over an enclosing workspace.
        packages.sort_by_key(|p| std::cmp::Reverse(p.root.components().count()));
        Self { packages }
    }

    /// The recognised packages, ordered by name.
    #[must_use]
    pub fn packages(&self) -> Vec<PackageInfo> {
        let mut infos: Vec<PackageInfo> = self
            .packages
            .iter()
            .map(|p| PackageInfo {
                name: p.name.clone(),
                root: p.root.clone(),
            })
            .collect();
        infos.sort_by(|a, b| a.name.cmp(&b.name));
        infos
    }

    /// Attribute an absolute file path to its package name and target kind.
    ///
    /// Files outside every recognised package resolve to
    /// `(None, TargetKind::Unknown)`.
    #[must_use]
    pub fn classify(&self, absolute_path: &Path) -> (Option<String>, TargetKind) {
        let Some(package) = self
            .packages
            .iter()
            .find(|p| absolute_path.starts_with(&p.root))
        else {
            return (None, TargetKind::Unknown);
        };
        let kind = package.target_kind(absolute_path);
        (Some(package.name.clone()), kind)
    }
}

impl Package {
    fn target_kind(&self, absolute_path: &Path) -> TargetKind {
        if self
            .lib_path
            .as_ref()
            .is_some_and(|lib| lib == absolute_path)
        {
            return TargetKind::Library;
        }
        if self.bin_paths.iter().any(|bin| bin == absolute_path) {
            return TargetKind::Binary;
        }
        let Ok(rel) = absolute_path.strip_prefix(&self.root) else {
            return TargetKind::Unknown;
        };
        classify_by_convention(rel)
    }
}

/// Classify a package-relative path by Cargo's default layout conventions.
fn classify_by_convention(rel: &Path) -> TargetKind {
    let components: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    match components.as_slice() {
        ["build.rs"] => TargetKind::BuildScript,
        ["src", "main.rs"] | ["src", "bin", ..] => TargetKind::Binary,
        ["src", ..] => TargetKind::Library,
        ["tests", ..] => TargetKind::Test,
        ["benches", ..] => TargetKind::Bench,
        ["examples", ..] => TargetKind::Example,
        _ => TargetKind::Unknown,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn write_manifest(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("Cargo.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn conventional_paths_map_to_target_kinds() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(dir.path(), "[package]\nname = \"demo\"\n");
        let layout = CargoLayout::from_manifests(&[manifest]);

        let cases = [
            ("src/lib.rs", TargetKind::Library),
            ("src/engine/mod.rs", TargetKind::Library),
            ("src/main.rs", TargetKind::Binary),
            ("src/bin/tool.rs", TargetKind::Binary),
            ("tests/it.rs", TargetKind::Test),
            ("benches/bench.rs", TargetKind::Bench),
            ("examples/demo.rs", TargetKind::Example),
            ("build.rs", TargetKind::BuildScript),
        ];
        for (rel, expected) in cases {
            let (pkg, kind) = layout.classify(&dir.path().join(rel));
            assert_eq!(pkg.as_deref(), Some("demo"), "{rel}");
            assert_eq!(kind, expected, "{rel}");
        }
    }

    #[test]
    fn nested_package_wins_over_enclosing_workspace() {
        let root = tempfile::tempdir().unwrap();
        let workspace = write_manifest(root.path(), "[workspace]\nmembers = [\"inner\"]\n");
        let inner_dir = root.path().join("inner");
        std::fs::create_dir_all(&inner_dir).unwrap();
        let inner = write_manifest(&inner_dir, "[package]\nname = \"inner\"\n");
        let layout = CargoLayout::from_manifests(&[workspace, inner]);

        let (pkg, kind) = layout.classify(&inner_dir.join("src/lib.rs"));
        assert_eq!(pkg.as_deref(), Some("inner"));
        assert_eq!(kind, TargetKind::Library);
    }

    #[test]
    fn explicit_lib_path_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            dir.path(),
            "[package]\nname = \"demo\"\n[lib]\npath = \"lib/entry.rs\"\n",
        );
        let layout = CargoLayout::from_manifests(&[manifest]);
        let (_, kind) = layout.classify(&dir.path().join("lib/entry.rs"));
        assert_eq!(kind, TargetKind::Library);
    }

    #[test]
    fn files_outside_any_package_are_unknown() {
        let layout = CargoLayout::default();
        let (pkg, kind) = layout.classify(Path::new("/tmp/loose/file.rs"));
        assert_eq!(pkg, None);
        assert_eq!(kind, TargetKind::Unknown);
    }

    #[test]
    fn workspace_only_manifest_yields_no_packages() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(dir.path(), "[workspace]\nmembers = []\n");
        let layout = CargoLayout::from_manifests(&[manifest]);
        assert!(layout.packages().is_empty());
    }
}
