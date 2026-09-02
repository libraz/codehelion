//! Discovering a configuration file, reading it, and recording where it
//! came from.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::Config;

/// File name discovered at a scan root.
pub const CONFIG_FILE_NAME: &str = "codehelion.toml";

/// Where the resolved configuration came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Loaded from a file the user named with `--config`.
    ///
    /// Naming a configuration is an explicit authority decision. In
    /// particular, path-like settings in it are not treated as values supplied
    /// by the repository being scanned.
    Explicit(PathBuf),
    /// Found at the scanned root.
    ///
    /// A discovered file can belong to the tree being inspected, so consumers
    /// must treat path-like settings in it as untrusted unless they first
    /// confine them to that tree.
    Discovered(PathBuf),
    /// No file found; built-in defaults were used.
    Defaults,
}

impl ConfigSource {
    /// The file this configuration was read from, for quoting back to a
    /// reader; `None` when no file was read.
    ///
    /// Deliberately not a trust decision, and it cannot be made into one: it
    /// answers where a setting was written down, not who is entitled to it.
    /// Attributing a configured place to whoever chose it happens in one
    /// place inside this module, and this is not it.
    #[must_use]
    pub fn file(&self) -> Option<&Path> {
        match self {
            Self::Explicit(path) | Self::Discovered(path) => Some(path),
            Self::Defaults => None,
        }
    }
}

/// A resolved configuration together with its provenance.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedConfig {
    /// The effective configuration.
    pub config: Config,
    /// Where it came from.
    pub source: ConfigSource,
}

/// Resolve the configuration for a scan rooted at `start_dir`.
///
/// When `explicit` is given, that file is loaded and a missing or invalid file
/// is an error. Otherwise only `start_dir/codehelion.toml` is used, falling
/// back to defaults when it does not exist.
///
/// # Errors
///
/// Returns an error if a named or discovered file cannot be read or parsed.
pub fn load(explicit: Option<&Path>, start_dir: &Path) -> Result<ResolvedConfig> {
    if let Some(path) = explicit {
        let config = read_file(path)?;
        return Ok(ResolvedConfig {
            config,
            source: ConfigSource::Explicit(path.to_path_buf()),
        });
    }
    match find_at_root(start_dir) {
        Some(path) => {
            let config = read_file(&path)?;
            Ok(ResolvedConfig {
                config,
                source: ConfigSource::Discovered(path),
            })
        }
        None => Ok(ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Defaults,
        }),
    }
}

fn read_file(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading configuration file {}", path.display()))?;
    Config::from_toml(&text).with_context(|| format!("in configuration file {}", path.display()))
}

/// Return the configuration file immediately inside `start_dir`, if present.
fn find_at_root(start_dir: &Path) -> Option<PathBuf> {
    let candidate = start_dir.join(CONFIG_FILE_NAME);
    candidate.is_file().then_some(candidate)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn invalid_numeric_value_names_its_configuration_file() {
        let directory = tempfile::tempdir().expect("temporary configuration directory");
        let path = directory.path().join(CONFIG_FILE_NAME);
        std::fs::write(&path, "[limits]\npair-budget = 0").expect("write invalid configuration");

        let error = load(Some(&path), directory.path())
            .expect_err("an explicit invalid configuration must fail");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("limits.pair-budget"));
        assert!(rendered.contains(&path.display().to_string()));
    }

    #[test]
    fn explicit_missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(load(Some(&missing), dir.path()).is_err());
    }

    #[test]
    fn explicitly_named_and_discovered_configurations_keep_distinct_provenance() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join(CONFIG_FILE_NAME);
        std::fs::write(&file, "database = \"audit.db\"").unwrap();

        let explicit = load(Some(&file), dir.path()).unwrap();
        assert_eq!(explicit.source, ConfigSource::Explicit(file.clone()));

        let discovered = load(None, dir.path()).unwrap();
        assert_eq!(discovered.source, ConfigSource::Discovered(file));
    }

    #[test]
    fn discovery_does_not_inherit_a_parent_configuration() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(CONFIG_FILE_NAME), "min-clone-tokens = 15").unwrap();
        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let resolved = load(None, &nested).unwrap();
        assert_eq!(resolved.config, Config::default());
        assert_eq!(resolved.source, ConfigSource::Defaults);
    }

    #[test]
    fn no_file_resolves_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = load(None, dir.path()).unwrap();
        assert_eq!(resolved.source, ConfigSource::Defaults);
        assert_eq!(resolved.config, Config::default());
    }
}
