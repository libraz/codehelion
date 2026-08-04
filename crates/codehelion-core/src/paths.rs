//! Resolving a path to the single spelling everything else compares against.

use std::path::{Path, PathBuf};

/// Resolve `path` to its canonical location, spelled the way the platform
/// ordinarily spells it.
///
/// This is [`std::fs::canonicalize`] everywhere except in what it does with
/// Windows' answer. There, canonicalizing returns a *verbatim* path — the
/// `\\?\` form, which exists so that names the ordinary rules cannot express
/// are still reachable. Two things follow from keeping that form. It is what
/// a person is shown, in place of the path they typed. And it is what gets
/// recorded as the identity of a scanned tree, so a later invocation that
/// arrives spelled ordinarily names a different tree and finds nothing of
/// what was recorded.
///
/// The prefix is therefore dropped whenever the remainder still names the
/// same file, and kept whenever it does not — because for those paths the
/// verbatim form is not decoration, it is the only spelling that works.
///
/// # Errors
///
/// Returns whatever [`std::fs::canonicalize`] returns: the path has to exist
/// and every component of it has to be traversable.
#[inline]
pub fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    let resolved = path.canonicalize()?;
    #[cfg(windows)]
    {
        Ok(simplify(&resolved).unwrap_or(resolved))
    }
    #[cfg(not(windows))]
    {
        Ok(resolved)
    }
}

/// Rewrite a Windows verbatim path in the ordinary form, or decline.
///
/// Declining is the safe answer and is taken whenever anything about the path
/// makes the two forms mean different things.
#[cfg(windows)]
fn simplify(path: &Path) -> Option<PathBuf> {
    use std::path::{Component, Prefix};

    // What the ordinary rules cap a path at. A longer one is reachable only
    // through the verbatim form, which is the case this prefix exists for.
    const PATH_LIMIT: usize = 260;

    let Some(Component::Prefix(prefix)) = path.components().next() else {
        return None;
    };
    // A verbatim UNC share could be rewritten too, and a device path
    // (`\\?\PIPE\...`) could not: nothing outside the verbatim form names it
    // at all. Only a local drive is rewritten here, because that is the form
    // a repository is scanned from and the one whose spelling a person
    // recognises.
    if !matches!(prefix.kind(), Prefix::VerbatimDisk(_)) {
        return None;
    }
    // A path that is not UTF-8 keeps the form it was given: comparing it
    // component by component below would mean deciding what its bytes say.
    let simplified = path.to_str()?.strip_prefix(r"\\?\")?;
    if simplified.len() >= PATH_LIMIT {
        return None;
    }
    Path::new(simplified)
        .components()
        .skip(1)
        .all(ordinarily_reachable)
        .then(|| PathBuf::from(simplified))
}

/// Whether a path component means the same thing outside the verbatim form.
///
/// Three kinds do not. A name the system reserves for a device is resolved to
/// that device rather than to the file. A name ending in a dot or a space has
/// those characters stripped. And a `.` or `..` is resolved rather than taken
/// literally, which is the whole difference the verbatim form makes.
#[cfg(windows)]
fn ordinarily_reachable(component: std::path::Component<'_>) -> bool {
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    const NUMBERED: [&str; 2] = ["COM", "LPT"];

    let std::path::Component::Normal(name) = component else {
        return false;
    };
    let Some(name) = name.to_str() else {
        return false;
    };
    if name.ends_with('.') || name.ends_with(' ') {
        return false;
    }
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    if RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return false;
    }
    !NUMBERED.iter().any(|device| {
        stem.len() == device.len() + 1
            && stem[..device.len()].eq_ignore_ascii_case(device)
            && matches!(stem.as_bytes()[device.len()], b'1'..=b'9')
    })
}

#[cfg(test)]
mod tests;
