//! Discovering a configuration file, reading it, and recording where it
//! came from.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

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
    match find_at_root(start_dir)? {
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

/// The most of a configuration file that is read.
///
/// A real configuration is a few kilobytes. The ceiling exists because a
/// discovered file is supplied by the tree being inspected, and one large
/// enough to exhaust memory must be refused with a sentence instead.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

fn read_file(path: &Path) -> Result<Config> {
    let text = read_config_text(path)?;
    Config::from_toml(&text).with_context(|| format!("in configuration file {}", path.display()))
}

/// Read a configuration file's text, refusing one above [`MAX_CONFIG_BYTES`].
///
/// The byte count comes from the read rather than from metadata, so a file
/// that reports a misleading length is still bounded before it is held.
fn read_config_text(path: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_CONFIG_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
        })
        .with_context(|| format!("reading configuration file {}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_CONFIG_BYTES {
        bail!(
            "configuration file {} exceeds the maximum of {MAX_CONFIG_BYTES} bytes",
            path.display()
        );
    }
    String::from_utf8(bytes)
        .with_context(|| format!("reading configuration file {}", path.display()))
}

/// Return the configuration file immediately inside `start_dir`, if present.
///
/// The file is supplied by the tree being inspected, so it is read only as a
/// regular file sitting in it: a link could point anywhere on the machine, and
/// the first line that failed to parse would be quoted back in the error.
fn find_at_root(start_dir: &Path) -> Result<Option<PathBuf>> {
    let candidate = start_dir.join(CONFIG_FILE_NAME);
    match std::fs::symlink_metadata(&candidate) {
        Ok(metadata) if metadata.file_type().is_symlink() => bail!(
            "refusing configuration file {}: it is a link, and a configuration found in the scanned tree is read only as a regular file inside it; name the file with --config to use it",
            candidate.display()
        ),
        Ok(metadata) => Ok(metadata.is_file().then_some(candidate)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error)
            .with_context(|| format!("checking configuration file {}", candidate.display())),
    }
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

    #[cfg(unix)]
    #[test]
    fn a_discovered_configuration_that_is_a_link_is_refused_without_quoting_it() {
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("secret");
        std::fs::write(&target, "private-key-material\n").unwrap();
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join(CONFIG_FILE_NAME);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let rendered = format!("{:#}", load(None, root.path()).unwrap_err());
        assert!(rendered.contains("is a link"), "{rendered}");
        assert!(rendered.contains(&link.display().to_string()), "{rendered}");
        assert!(!rendered.contains("private-key-material"), "{rendered}");

        // Named on the command line, the same file keeps operator authority.
        let named = load(Some(&link), root.path()).unwrap_err();
        assert!(!format!("{named:#}").contains("is a link"));
    }

    #[test]
    fn a_configuration_above_the_ceiling_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(CONFIG_FILE_NAME);
        let oversized = usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1;
        std::fs::write(&path, "#".repeat(oversized)).unwrap();

        let rendered = format!("{:#}", load(None, root.path()).unwrap_err());
        assert!(rendered.contains("exceeds the maximum"), "{rendered}");
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
