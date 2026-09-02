//! Where a helper program is looked for, and who is allowed to say so.

use std::path::{Path, PathBuf};

/// Who chose where a helper is looked for.
///
/// Starting a program is not something a location alone may decide, so every
/// configured location arrives with the answer to this question attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperAuthority {
    /// An operator: a command line, or a configuration file the caller named.
    Operator,
    /// The tree under analysis, through a configuration file found inside it.
    Scanned,
}

/// Where a helper was configured to be, together with who said so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfiguredHelper<'a> {
    /// The configured location.
    pub path: &'a Path,
    /// Who chose it.
    pub authority: HelperAuthority,
}

impl<'a> ConfiguredHelper<'a> {
    /// A location an operator chose.
    #[must_use]
    pub const fn operator(path: &'a Path) -> Self {
        Self {
            path,
            authority: HelperAuthority::Operator,
        }
    }

    /// A location the tree under analysis supplied.
    #[must_use]
    pub const fn scanned(path: &'a Path) -> Self {
        Self {
            path,
            authority: HelperAuthority::Scanned,
        }
    }
}

/// Where to look for a helper, in the order the search tries.
///
/// An operator's configured path is tried first. The plan for this search put
/// configuration last, which is the wrong way round: a setting that loses to
/// whatever happens to be on `PATH` cannot be used to pin a helper, which is
/// the only reason to write one down.
///
/// A location the scanned tree supplied is passed over as though it had not
/// been written, and the search goes on beside this executable and along
/// `PATH`. Following it would let a repository name the program that a scan of
/// it starts, and there is no confining such a path the way a storage path is
/// confined — a program inside the tree is exactly what it would name. Passing
/// it over rather than refusing keeps the repository from choosing the helper
/// and from denying the run one.
#[must_use]
pub fn locate(name: &str, configured: Option<ConfiguredHelper<'_>>) -> Option<PathBuf> {
    if let Some(configured) = configured
        && configured.authority == HelperAuthority::Operator
    {
        return configured
            .path
            .is_file()
            .then(|| configured.path.to_path_buf());
    }
    let file = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    if let Ok(current) = std::env::current_exe()
        && let Some(directory) = current.parent()
    {
        let beside = directory.join(&file);
        if beside.is_file() {
            return Some(beside);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(&file))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_path_that_is_not_there_is_not_replaced_by_one_that_is() {
        // Falling back to PATH would silently run a different build than the
        // one the setting names, which is the failure a setting exists to stop.
        let missing = Path::new("/nonexistent/codehelion-backend-rust");
        assert_eq!(
            locate(
                "codehelion-backend-rust",
                Some(ConfiguredHelper::operator(missing))
            ),
            None
        );
    }

    #[test]
    fn a_helper_nobody_has_installed_is_not_found() {
        assert_eq!(locate("codehelion-backend-nothing-at-all", None), None);
    }

    #[test]
    fn a_program_the_scanned_tree_named_is_never_where_a_helper_is_looked_for() {
        // One file that certainly exists, offered by each of the two
        // authorities: who chose it, not whether it is there, is what decides.
        let present = std::env::current_exe().expect("this test is a file on disk");
        assert_eq!(
            locate(
                "codehelion-backend-nothing-at-all",
                Some(ConfiguredHelper::operator(&present))
            ),
            Some(present.clone())
        );
        assert_eq!(
            locate(
                "codehelion-backend-nothing-at-all",
                Some(ConfiguredHelper::scanned(&present))
            ),
            None
        );
    }
}
