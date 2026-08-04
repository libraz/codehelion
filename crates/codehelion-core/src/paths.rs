//! Resolving a path to the single spelling everything else compares against.

use std::path::{Path, PathBuf};

/// What the ordinary Windows rules cap a path at. A longer one is reachable
/// only through the verbatim form, which is the case that form exists for.
#[cfg(any(windows, test))]
const PATH_LIMIT: usize = 260;

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
pub fn canonical(path: &Path) -> std::io::Result<PathBuf> {
    let resolved = path.canonicalize()?;
    #[cfg(windows)]
    {
        // A path that is not UTF-8 keeps the form it was given: reading it
        // apart below would mean deciding what its bytes say.
        let simplified = resolved.to_str().and_then(simplify).map(PathBuf::from);
        Ok(simplified.unwrap_or(resolved))
    }
    #[cfg(not(windows))]
    {
        Ok(resolved)
    }
}

// Compiled where it is used and where it is checked. The rule is about
// Windows paths, and the tests that hold it to account are run everywhere —
// which is the only reason a mistake in it is found by anything other than a
// Windows machine.
/// Rewrite a Windows verbatim path in the ordinary form, or decline.
///
/// Read as text rather than through [`Path`], because on every platform but
/// one `Path` does not know what these strings are — and a rule that can only
/// be exercised where it is used is a rule nobody is checking.
///
/// Declining is the safe answer, and is taken whenever anything about the
/// path makes the two forms name different things.
#[cfg(any(windows, test))]
fn simplify(path: &str) -> Option<&str> {
    let simplified = path.strip_prefix(r"\\?\")?;
    if simplified.len() >= PATH_LIMIT {
        return None;
    }
    // A local drive, and nothing else. A share (`UNC\server\...`) would be a
    // different rewrite, and a device (`PIPE\name`) has no other spelling at
    // all.
    let (drive, rest) = simplified.split_at_checked(3)?;
    let mut spelling = drive.chars();
    if !spelling
        .next()
        .is_some_and(|letter| letter.is_ascii_alphabetic())
        || spelling.next() != Some(':')
        || spelling.next() != Some('\\')
    {
        return None;
    }
    // The drive's own root has no components to check and is reached the same
    // way under either form.
    if rest.is_empty() {
        return Some(simplified);
    }
    rest.split('\\')
        .all(ordinarily_reachable)
        .then_some(simplified)
}

/// Whether a path component means the same thing outside the verbatim form.
///
/// Four kinds do not. A name the system reserves for a device is resolved to
/// that device rather than to the file. A name ending in a dot or a space has
/// those characters stripped. A `.` or `..` is resolved rather than taken
/// literally, which is the whole difference the verbatim form makes. And an
/// empty component is a repeated separator, which the ordinary rules collapse
/// and the verbatim form keeps.
#[cfg(any(windows, test))]
fn ordinarily_reachable(component: &str) -> bool {
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    const NUMBERED: [&str; 2] = ["COM", "LPT"];

    if matches!(component, "" | "." | "..") || component.ends_with('.') || component.ends_with(' ')
    {
        return false;
    }
    let stem = component.split('.').next().unwrap_or(component).trim_end();
    if RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
    {
        return false;
    }
    // `COM1` through `COM9` and the same for `LPT`. `COM10` is a file.
    !NUMBERED.iter().any(|device| {
        stem.len() == device.len() + 1
            && stem
                .get(..device.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(device))
            && stem
                .as_bytes()
                .last()
                .is_some_and(|digit| digit.is_ascii_digit() && *digit != b'0')
    })
}

#[cfg(test)]
mod tests;
