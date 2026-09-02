//! How this process configures and reads a Cargo project.
//!
//! One configuration serves both the description a handshake asks for and the
//! load a request is answered from, so what a run is told it was analysed under
//! and what it was actually analysed under cannot drift apart.

use std::path::Path;

use codehelion_helper::protocol::BuildDescription;

use super::Permissions;
use super::toolchain::{HelperToolchain, helper_toolchain};

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
pub(super) fn cargo_config_for_workspace(
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

pub(super) fn project_workspace_with_toolchain(
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
pub(super) fn describe_workspace(manifest: &Path) -> Result<BuildDescription, String> {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use super::super::{Outcome, Permissions, Workspaces};
    use super::{PROJECT_WORKSPACE_LOADS, cargo_config, helper_toolchain};

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
}
