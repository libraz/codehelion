use super::*;

use std::path::PathBuf;

#[cfg(unix)]
#[test]
fn non_utf8_path_keys_stay_distinct_from_each_other_and_utf8_names() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let first = PathBuf::from(OsString::from_vec(b"src/\x80.rs".to_vec()));
    let second = PathBuf::from(OsString::from_vec(b"src/\x81.rs".to_vec()));
    let first_key = path_key(&first);
    let second_key = path_key(&second);
    assert_ne!(first_key, second_key);
    assert_ne!(first_key, "src/\u{fffd}.rs");
    assert!(first_key.starts_with('\u{001f}'));
    assert!(display_path(&first_key).starts_with("<non-UTF-8 path: "));
    assert!(!display_path(&first_key).contains("codehelion-path-bytes"));
    assert_eq!(path_key(Path::new("src/plain.rs")), "src/plain.rs");
}

/// The property a lookup depends on. A tree is recorded under the key of the
/// path a scan resolved and looked up under the key of the path a later
/// command resolved, and on Windows those two arrive spelled differently
/// often enough that the key has to settle it.
#[test]
#[cfg(windows)]
fn either_separator_names_one_tree() {
    assert_eq!(
        path_key(Path::new(r"C:\Users\name\project")),
        path_key(Path::new("C:/Users/name/project"))
    );
    assert_eq!(
        path_key(Path::new(r"C:\Users\name\project")),
        "C:/Users/name/project"
    );
}

#[test]
fn a_key_that_was_never_escaped_reads_back_as_itself() {
    for path in ["src/plain.rs", "src/a b.rs", "src/\u{3042}.rs"] {
        assert_eq!(display_path(&path_key(Path::new(path))), path);
    }
}

/// The sentinel is reserved: a path that begins with it is escaped like any
/// other unrepresentable name, so that no real path can be mistaken for the
/// encoding of a different one.
#[test]
fn a_path_spelled_like_the_encoding_is_escaped_too() {
    let impostor = PathBuf::from(format!("{ESCAPED_PATH_PREFIX}deadbeef"));
    let key = path_key(&impostor);
    assert_ne!(key, impostor.to_string_lossy());
    assert_eq!(display_path(&key), impostor.to_string_lossy());
}

#[test]
fn a_key_that_is_not_a_whole_number_of_bytes_is_refused() {
    let truncated = format!("{ESCAPED_PATH_PREFIX}abc");
    assert_eq!(display_path(&truncated), "<invalid stored path key>");
    let unreadable = format!("{ESCAPED_PATH_PREFIX}zz");
    assert_eq!(display_path(&unreadable), "<invalid stored path key>");
}
