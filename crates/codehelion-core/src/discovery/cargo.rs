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
    name: Option<String>,
    path: Option<String>,
}

/// One Cargo package, rooted at the directory holding its manifest.
#[derive(Debug, Clone)]
struct Package {
    root: PathBuf,
    name: String,
    /// The `[lib] name`, when the manifest set one.
    lib_name: Option<String>,
    /// Absolute path of an explicit `[lib] path`, if the manifest set one.
    lib_path: Option<PathBuf>,
    /// Explicit `[[bin]]` entries that gave both a name and a path.
    bins: Vec<Binary>,
    /// Absolute paths of explicit `[[bin]] path` entries.
    bin_paths: Vec<PathBuf>,
}

/// An explicitly declared binary target.
#[derive(Debug, Clone)]
struct Binary {
    name: String,
    path: PathBuf,
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
            let lib = manifest.lib.unwrap_or(TargetSection {
                name: None,
                path: None,
            });
            let lib_path = lib.path.map(|path| root.join(path));
            let bins: Vec<Binary> = manifest
                .bin
                .iter()
                .filter_map(|bin| {
                    Some(Binary {
                        name: bin.name.clone()?,
                        path: root.join(bin.path.clone()?),
                    })
                })
                .collect();
            let bin_paths = manifest
                .bin
                .into_iter()
                .filter_map(|bin| bin.path)
                .map(|path| root.join(path))
                .collect();
            packages.push(Package {
                root: root.to_path_buf(),
                name: package.name,
                lib_name: lib.name,
                lib_path,
                bins,
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

    /// The name a compiler knows `absolute_path`'s crate by, when the layout
    /// says which crate that is.
    ///
    /// A compiler names a crate after the *target*, not the package: one
    /// package is a library, some binaries and a test crate per test file, and
    /// asking about a file under the wrong one gets an answer about somebody
    /// else's code. Dashes become underscores because that mapping is the
    /// compiler's — a crate name is an identifier and a package name need not
    /// be — rather than a guess about spelling.
    ///
    /// `None` where the layout does not settle it: a file under `tests/` that
    /// is not a target's own entry point is a module of one of them, and which
    /// one is written in the code rather than in the manifest. Asking under a
    /// guessed crate would produce an answer about a crate the file is not in,
    /// which is worse than reporting that nobody asked.
    #[must_use]
    pub fn crate_name(&self, absolute_path: &Path) -> Option<String> {
        let package = self
            .packages
            .iter()
            .find(|p| absolute_path.starts_with(&p.root))?;
        package
            .crate_name(absolute_path)
            .map(|name| identifier(&name))
    }
}

/// A crate name as the compiler spells it.
fn identifier(name: &str) -> String {
    name.replace('-', "_")
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

    /// Which of this package's targets holds `absolute_path`, by target name.
    fn crate_name(&self, absolute_path: &Path) -> Option<String> {
        // A declared target settles it whatever the path looks like, which is
        // the point of declaring one.
        if let Some(bin) = self.bins.iter().find(|bin| bin.path == absolute_path) {
            return Some(bin.name.clone());
        }
        if self
            .lib_path
            .as_ref()
            .is_some_and(|lib| lib == absolute_path)
        {
            return Some(self.lib_name.clone().unwrap_or_else(|| self.name.clone()));
        }
        let rel = absolute_path.strip_prefix(&self.root).ok()?;
        let components: Vec<&str> = rel
            .components()
            .filter_map(|c| c.as_os_str().to_str())
            .collect();
        match components.as_slice() {
            // The default binary is the one target named after the package
            // rather than after a file.
            ["src", "main.rs"] => Some(self.name.clone()),
            // A binary, test, bench or example is its own crate, named after
            // the file that is its entry point — and only that file is one.
            ["src", "bin", entry] | ["tests" | "benches" | "examples", entry] => {
                Some(stem(entry)?.to_string())
            }
            ["src", "bin", target, "main.rs"]
            | ["tests" | "benches" | "examples", target, "main.rs"] => Some((*target).to_string()),
            // A module of one of the binaries, and which one is written in the
            // code rather than in the manifest.
            ["src", "bin", ..] => None,
            // Everything else under `src` is a module of the library. A
            // package whose only target is a binary under another name gets
            // the wrong name here, and the answer to a name that names no
            // crate is that there is no build information for it — which is
            // the safe direction to be wrong in.
            ["src", ..] => Some(self.lib_name.clone().unwrap_or_else(|| self.name.clone())),
            _ => None,
        }
    }
}

/// The target name a single-file entry point carries, or `None` when the file
/// is not a Rust source at all.
fn stem(entry: &str) -> Option<&str> {
    entry.strip_suffix(".rs")
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

    /// A compiler is asked about a crate, and a package is not one. Every
    /// entry point below is a crate of its own, and a module file belongs to
    /// the crate whose tree it sits in.
    #[test]
    fn each_target_is_the_crate_its_files_belong_to() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(dir.path(), "[package]\nname = \"demo\"\n");
        let layout = CargoLayout::from_manifests(&[manifest]);
        let cases = [
            ("src/lib.rs", Some("demo")),
            ("src/engine/mod.rs", Some("demo")),
            ("src/main.rs", Some("demo")),
            ("src/bin/tool.rs", Some("tool")),
            ("src/bin/tool/main.rs", Some("tool")),
            ("tests/it.rs", Some("it")),
            ("benches/speed.rs", Some("speed")),
            ("examples/demo.rs", Some("demo")),
            // A module of some test crate; which one is written in the code.
            ("tests/common/helper.rs", None),
            ("src/bin/tool/helper.rs", None),
            ("build.rs", None),
        ];
        for (rel, expected) in cases {
            assert_eq!(
                layout.crate_name(&dir.path().join(rel)).as_deref(),
                expected,
                "{rel}"
            );
        }
    }

    /// A declared target says what it is called, and a name a manifest gives
    /// is not derivable from any path.
    #[test]
    fn a_declared_target_is_known_by_the_name_it_declared() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(
            dir.path(),
            "[package]\nname = \"demo\"\n\
             [lib]\nname = \"engine\"\npath = \"lib/entry.rs\"\n\
             [[bin]]\nname = \"tool\"\npath = \"cmd/run.rs\"\n",
        );
        let layout = CargoLayout::from_manifests(&[manifest]);
        assert_eq!(
            layout
                .crate_name(&dir.path().join("lib/entry.rs"))
                .as_deref(),
            Some("engine")
        );
        assert_eq!(
            layout.crate_name(&dir.path().join("cmd/run.rs")).as_deref(),
            Some("tool")
        );
        // The library's own name reaches its modules too.
        assert_eq!(
            layout
                .crate_name(&dir.path().join("src/parse.rs"))
                .as_deref(),
            Some("engine")
        );
    }

    /// Cargo lets a package be called what a compiler cannot: the crate is
    /// known by the identifier, and that mapping belongs to the compiler
    /// rather than to a guess about how names are spelled here.
    #[test]
    fn a_dash_in_a_package_name_is_an_underscore_in_the_crate_name() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(dir.path(), "[package]\nname = \"my-crate\"\n");
        let layout = CargoLayout::from_manifests(&[manifest]);
        assert_eq!(
            layout.crate_name(&dir.path().join("src/lib.rs")).as_deref(),
            Some("my_crate")
        );
    }

    #[test]
    fn a_file_outside_every_package_belongs_to_no_crate() {
        let layout = CargoLayout::default();
        assert_eq!(layout.crate_name(Path::new("/tmp/loose/file.rs")), None);
    }

    #[test]
    fn workspace_only_manifest_yields_no_packages() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_manifest(dir.path(), "[workspace]\nmembers = []\n");
        let layout = CargoLayout::from_manifests(&[manifest]);
        assert!(layout.packages().is_empty());
    }
}
