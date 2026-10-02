//! Reading a linker map from disk.

use super::*;

const MAP_LINE: &str = ".text.render 0x1000 0x20 build/render.o\n";

#[test]
fn a_map_naming_non_utf8_bytes_is_read_with_the_replacement_character() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("app.map");
    let mut bytes = MAP_LINE.as_bytes().to_vec();
    bytes.extend(b"# built in \xff\xfe\n");
    fs::write(&path, bytes).unwrap();

    let entries = read_linker_map(Some(FilePath::new(&path))).unwrap();

    assert!(!entries.is_empty());
}

#[test]
fn a_map_over_the_limit_is_refused_after_reading_no_more_than_the_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("huge.map");
    fs::File::create(&path)
        .unwrap()
        .set_len(MAX_LINKER_MAP_BYTES + 1)
        .unwrap();

    let error = read_linker_map(Some(FilePath::new(&path))).unwrap_err();

    assert!(error.to_string().contains("exceeds"), "{error:#}");
}

/// A device reports no length and never ends, so it is the file that a size
/// check on metadata lets through.
#[cfg(unix)]
#[test]
fn a_device_is_refused_rather_than_read() {
    let error = read_linker_map(Some(FilePath::new("/dev/zero"))).unwrap_err();

    assert!(
        error.to_string().contains("not a regular file"),
        "{error:#}"
    );
}
