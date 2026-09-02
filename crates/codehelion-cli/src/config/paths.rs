//! Attributing every place a configuration names to whoever chose it.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the module answers the command layer's authority question about a configured place"
)]

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{Config, ConfigSource, Helpers, ResolvedConfig};
use crate::provenance::{Authority, FromScannedTree, OperatorSupplied};

/// Resolve configured helper paths with command-line overrides taking priority.
///
/// A helper location is the name of a program this run starts, so it is taken
/// only from the operator: `--helper NAME=PATH`, or a configuration file the
/// caller named. The `[helpers]` section of a configuration discovered at the
/// scan root is disregarded, because that file can belong to the tree under
/// analysis and nothing confines such a path the way [`Config::database`] is
/// confined — a program inside the tree is exactly what it would name.
///
/// Disregarded rather than refused: `--untrusted` exists to scan a repository
/// nobody vouches for, and a repository that could end the scan by writing one
/// section would be choosing whether it gets audited.
/// [`disregarded_helpers_note`] is the sentence that keeps the omission from
/// looking like a helper nobody installed.
///
/// # Errors
///
/// Returns an error for an unknown helper name, an empty path, a malformed
/// assignment, or a duplicate command-line setting.
pub fn helper_paths(resolved: &ResolvedConfig, overrides: &[String]) -> Result<Helpers> {
    let configured = configured_paths(resolved);
    let mut paths = Helpers {
        rust: operator_choice(configured.rust_helper),
        clang: operator_choice(configured.clang_helper),
    };
    let mut seen = std::collections::BTreeSet::new();
    for override_ in overrides {
        let Some((name, path)) = override_.split_once('=') else {
            bail!("--helper must be NAME=PATH (rust or clang)");
        };
        if path.is_empty() {
            bail!("--helper {name} has an empty path");
        }
        let slot = match name {
            "rust" => &mut paths.rust,
            "clang" => &mut paths.clang,
            _ => bail!("unknown helper {name:?}; expected rust or clang"),
        };
        if !seen.insert(name) {
            bail!("--helper {name} was specified more than once");
        }
        *slot = Some(PathBuf::from(path));
    }
    Ok(paths)
}

/// The path behind an authority the operator holds, or `None` for one the tree
/// under audit chose or for a setting nobody wrote.
fn operator_choice(configured: Option<Authority<&Path>>) -> Option<PathBuf> {
    match configured? {
        Authority::Operator(path) => Some(path.get().to_path_buf()),
        Authority::Tree(_) => None,
    }
}

/// Every setting a configuration can use to name a place on disk, each one
/// attributed to whoever chose it.
///
/// The one place that turns a [`ConfigSource`] into a trust decision. A
/// consumer receives the value and the question about it together and answers
/// by matching, instead of reaching into [`Config`] for a bare path and
/// remembering — or not — to ask where it came from.
pub(crate) struct ConfiguredPaths<'a> {
    /// Where the audit database goes.
    pub(crate) database: Authority<&'a Path>,
    /// The Rust compiler helper, when the configuration names one.
    pub(crate) rust_helper: Option<Authority<&'a Path>>,
    /// The Clang compiler helper, when the configuration names one.
    pub(crate) clang_helper: Option<Authority<&'a Path>>,
}

/// Attribute each of a resolved configuration's places on disk to whoever
/// chose it.
///
/// [`Config`] is taken apart exhaustively rather than read field by field: a
/// setting added to it stops this compiling until it says whether it names a
/// place on disk, which is the question a new path-like setting is otherwise
/// free to never be asked. Fields that name no place are bound and discarded
/// here, and the grouping says which is which.
pub(crate) fn configured_paths(resolved: &ResolvedConfig) -> ConfiguredPaths<'_> {
    let Config {
        // Patterns, measures and policy. None of these is opened, joined onto
        // a directory, or started as a program, so none of them carries an
        // authority question: a glob decides what is read out of the tree the
        // operator already pointed this run at.
        include: _,
        exclude: _,
        min_clone_tokens: _,
        entropy_ratio_floor: _,
        literal_normalization: _,
        languages: _,
        suppression: _,
        priority: _,
        limits: _,
        semantic: _,
        report: _,
        jobs: _,
        // The ledger names path globs and thresholds. A glob decides which of
        // the repository's own commits a count is taken over; none of it is
        // opened, joined onto a directory, or started as a program.
        seam: _,
        seam_tracking: _,
        // Places on disk: one the tool writes, two it starts as programs.
        database,
        helpers: Helpers { rust, clang },
    } = &resolved.config;
    let source = &resolved.source;
    ConfiguredPaths {
        database: attributed(source, database),
        rust_helper: rust.as_deref().map(|path| attributed(source, path)),
        clang_helper: clang.as_deref().map(|path| attributed(source, path)),
    }
}

/// Which party a configured value came from.
///
/// Naming a configuration file is an authority decision; finding one at the
/// scan root is not, because that file can belong to the tree under audit.
const fn attributed<'a>(source: &ConfigSource, path: &'a Path) -> Authority<&'a Path> {
    match source {
        ConfigSource::Discovered(_) => Authority::Tree(FromScannedTree::found(path)),
        ConfigSource::Explicit(_) => Authority::Operator(OperatorSupplied::from_command_line(path)),
        ConfigSource::Defaults => Authority::Operator(OperatorSupplied::from_this_build(path)),
    }
}

/// What to tell the reader when a configuration found in the scanned tree names
/// helper programs this run will not start, or `None` when it names none.
///
/// [`helper_paths`] makes the decision; this is what keeps it from reading as a
/// helper nobody installed. Returned as a sentence rather than printed here,
/// because the commands that resolve helpers write their results to different
/// places and this belongs beside neither of them.
#[must_use]
pub fn disregarded_helpers_note(resolved: &ResolvedConfig) -> Option<String> {
    let configured = configured_paths(resolved);
    let named: Vec<&str> = [
        ("rust", configured.rust_helper),
        ("clang", configured.clang_helper),
    ]
    .into_iter()
    .filter(|(_, configured)| matches!(configured, Some(Authority::Tree(_))))
    .map(|(name, _)| name)
    .collect();
    if named.is_empty() {
        return None;
    }
    // Only a file the tree supplied reaches here, and such a file has a path.
    let path = resolved.source.file()?;
    Some(format!(
        "ignoring [helpers] {} in {}: a configuration discovered in the scanned \
         repository cannot choose which program this run starts; pass \
         --helper NAME=PATH, or name the configuration with --config",
        named.join(" and "),
        path.display()
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn helper_paths_are_read_from_their_own_configuration_section() {
        let config = Config::from_toml(
            "[helpers]\nrust = \"/tools/codehelion-backend-rust\"\nclang = \"/tools/codehelion-backend-clang\"\n",
        )
        .unwrap();
        assert_eq!(
            config.helpers.rust,
            Some(PathBuf::from("/tools/codehelion-backend-rust"))
        );
        assert_eq!(
            config.helpers.clang,
            Some(PathBuf::from("/tools/codehelion-backend-clang"))
        );
    }

    /// A configuration holding both helper locations, as one provenance or another.
    fn resolved_with_helpers(source: ConfigSource) -> ResolvedConfig {
        ResolvedConfig {
            config: Config {
                helpers: Helpers {
                    rust: Some(PathBuf::from("/configured/rust")),
                    clang: Some(PathBuf::from("/configured/clang")),
                },
                ..Config::default()
            },
            source,
        }
    }

    #[test]
    fn command_line_helper_paths_override_configuration_and_validate_names() {
        let named = resolved_with_helpers(ConfigSource::Explicit(PathBuf::from("/named.toml")));
        let paths = helper_paths(
            &named,
            &[
                "rust=/command/rust".to_string(),
                "clang=/command/clang".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(paths.rust, Some(PathBuf::from("/command/rust")));
        assert_eq!(paths.clang, Some(PathBuf::from("/command/clang")));
        assert!(helper_paths(&named, &["other=/tool".to_string()]).is_err());
        assert!(helper_paths(&named, &["rust=".to_string()]).is_err());
    }

    /// Whether each place a configuration names came from the tree under audit.
    fn from_the_tree(resolved: &ResolvedConfig) -> (bool, bool, bool) {
        let places = configured_paths(resolved);
        (
            matches!(places.database, Authority::Tree(_)),
            matches!(places.rust_helper, Some(Authority::Tree(_))),
            matches!(places.clang_helper, Some(Authority::Tree(_))),
        )
    }

    #[test]
    fn every_place_a_configuration_names_is_attributed_to_whoever_chose_it() {
        // The file decides, and it is the same file for every setting in it: a
        // configuration whose database is the tree's word cannot also be the
        // operator's word about which program to start.
        let found = resolved_with_helpers(ConfigSource::Discovered(PathBuf::from(
            "/repository/codehelion.toml",
        )));
        assert_eq!(from_the_tree(&found), (true, true, true));

        let named = resolved_with_helpers(ConfigSource::Explicit(PathBuf::from("/named.toml")));
        assert_eq!(from_the_tree(&named), (false, false, false));

        // A setting nobody wrote is this build's own, which the tree had no part
        // in choosing; a helper nobody named is absent rather than distrusted.
        let defaults = ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Defaults,
        };
        let places = configured_paths(&defaults);
        assert!(matches!(places.database, Authority::Operator(_)));
        assert!(places.rust_helper.is_none());
        assert!(places.clang_helper.is_none());
    }

    #[test]
    fn a_named_configuration_may_say_where_the_helpers_are() {
        let named = resolved_with_helpers(ConfigSource::Explicit(PathBuf::from("/named.toml")));
        let paths = helper_paths(&named, &[]).unwrap();
        assert_eq!(paths.rust, Some(PathBuf::from("/configured/rust")));
        assert_eq!(paths.clang, Some(PathBuf::from("/configured/clang")));
        assert_eq!(disregarded_helpers_note(&named), None);
    }

    #[test]
    fn a_configuration_found_in_the_scanned_tree_may_not_say_where_the_helpers_are() {
        let found = resolved_with_helpers(ConfigSource::Discovered(PathBuf::from(
            "/repository/codehelion.toml",
        )));
        let paths = helper_paths(&found, &[]).unwrap();
        assert_eq!(paths, Helpers::default());
        // The command line still names one, and the section it displaces is one
        // that was never going to be read.
        let overridden = helper_paths(&found, &["rust=/command/rust".to_string()]).unwrap();
        assert_eq!(overridden.rust, Some(PathBuf::from("/command/rust")));
        assert_eq!(overridden.clang, None);
        let note = disregarded_helpers_note(&found).expect("the omission is stated");
        assert!(note.contains("rust and clang"), "{note}");
        assert!(note.contains("/repository/codehelion.toml"), "{note}");
    }

    #[test]
    fn a_configuration_found_in_the_scanned_tree_that_names_no_helper_says_nothing() {
        let found = ResolvedConfig {
            config: Config::default(),
            source: ConfigSource::Discovered(PathBuf::from("/repository/codehelion.toml")),
        };
        assert_eq!(disregarded_helpers_note(&found), None);
    }
}
