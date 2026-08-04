use super::*;

/// The property every recorded path depends on: two ways of naming one
/// directory have to arrive at the same value, or a second invocation records
/// a tree the first one never scanned.
#[test]
#[allow(clippy::expect_used)] // Test setup requires a real directory to resolve.
fn two_spellings_of_one_directory_resolve_alike() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let nested = directory.path().join("inner");
    std::fs::create_dir(&nested).expect("creating a directory to resolve");

    let direct = canonical(&nested).expect("resolving the directory");
    let roundabout = canonical(&nested.join("..").join("inner")).expect("resolving it again");

    assert_eq!(direct, roundabout);
}

/// What a person is shown. The verbatim prefix is Windows' answer to
/// `canonicalize`, not anything they typed, and it is not carried into the
/// path this tool then treats as the tree's name.
#[test]
#[cfg(windows)]
#[allow(clippy::expect_used)] // Test setup requires a real directory to resolve.
fn an_ordinary_directory_is_named_the_ordinary_way() {
    let directory = tempfile::tempdir().expect("a temporary directory");

    let resolved = canonical(directory.path()).expect("resolving the directory");

    assert!(
        !resolved.to_string_lossy().starts_with(r"\\?\"),
        "{} kept the verbatim prefix",
        resolved.display()
    );
    assert!(
        resolved.is_dir(),
        "{} no longer resolves",
        resolved.display()
    );
}

#[test]
fn a_local_drive_loses_the_prefix() {
    assert_eq!(
        simplify(r"\\?\C:\Users\name\project"),
        Some(r"C:\Users\name\project")
    );
    assert_eq!(simplify(r"\\?\D:\"), Some(r"D:\"));
    assert_eq!(simplify(r"\\?\c:\project"), Some(r"c:\project"));
}

/// Kept, because the ordinary form of these does not reach the same file —
/// or, in the case of a device path, does not reach anything.
#[test]
fn a_path_the_ordinary_rules_cannot_express_keeps_the_prefix() {
    let too_long = format!(r"\\?\C:\{}", "d".repeat(300));
    for path in [
        too_long.as_str(),
        r"\\?\C:\project\NUL",
        r"\\?\C:\project\nul.txt",
        r"\\?\C:\project\COM1",
        r"\\?\C:\project\lpt9\src",
        r"\\?\C:\project\name.",
        r"\\?\C:\project\name ",
        r"\\?\C:\project\.\src",
        r"\\?\C:\project\..\src",
        r"\\?\C:\project\\src",
        r"\\?\UNC\server\share\project",
        r"\\?\PIPE\name",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\project",
    ] {
        assert_eq!(simplify(path), None, "{path} was rewritten");
    }
}

/// A path that was never verbatim has nothing to drop, and neither has one
/// that is too short to say which drive it is on.
#[test]
fn a_path_without_the_prefix_is_left_alone() {
    for path in [r"C:\Users\name", "/usr/local", r"\\server\share", r"\\?\C"] {
        assert_eq!(simplify(path), None, "{path} was rewritten");
    }
}

/// A device name is only a device name on its own. Anything longer that
/// merely begins like one is an ordinary file.
#[test]
fn a_name_that_only_begins_like_a_device_is_an_ordinary_name() {
    for path in [
        r"\\?\C:\project\NULL.txt",
        r"\\?\C:\project\console",
        r"\\?\C:\project\COM10",
        r"\\?\C:\project\LPT0",
        r"\\?\C:\project\COM",
    ] {
        assert!(simplify(path).is_some(), "{path} was kept");
    }
}

/// The boundary the length check sits on, from both sides.
#[test]
fn a_path_is_measured_by_what_it_becomes() {
    let at_limit = format!(r"\\?\C:\{}", "d".repeat(PATH_LIMIT - 3));
    assert_eq!(simplify(&at_limit), None);
    let below_limit = format!(r"\\?\C:\{}", "d".repeat(PATH_LIMIT - 4));
    assert!(simplify(&below_limit).is_some());
}
