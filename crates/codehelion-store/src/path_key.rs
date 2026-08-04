//! How a filesystem path becomes a database key, and how it reads back.
//!
//! This is the store's contract rather than a caller's convenience. A run is
//! recorded under the key of the tree it read and looked up under the key of
//! the tree it is asked about, so the two have to be produced by one rule.
//! Producing it in a second place is how a lookup comes to miss a run that is
//! sitting in the table.

use std::path::Path;

/// Marks a key whose bytes are the path's own rather than its text.
const ESCAPED_PATH_PREFIX: &str = "\u{001f}codehelion-path-bytes:";

/// Render a filesystem path as a unique database key.
///
/// Ordinary UTF-8 paths keep their text, with one adjustment: on Windows the
/// separator is written as `/`, so that the same tree named through either
/// separator is one key rather than two.
///
/// A non-UTF-8 path is represented by its native encoded bytes rather than by
/// `to_string_lossy`, so two distinct names can never collapse into one
/// `SQLite` primary key. The reserved prefix is also escaped when it occurs in
/// an otherwise UTF-8 path.
#[must_use]
pub fn path_key(path: &Path) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = path.as_os_str().as_encoded_bytes();
    if let Ok(text) = std::str::from_utf8(bytes)
        && !text.starts_with(ESCAPED_PATH_PREFIX)
    {
        #[cfg(windows)]
        {
            return text.replace('\\', "/");
        }
        #[cfg(not(windows))]
        {
            return text.to_string();
        }
    }
    let mut encoded = ESCAPED_PATH_PREFIX.to_string();
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// Turn a stored path key into a safe human-facing path label.
///
/// The reversible storage encoding is deliberately not a public path format:
/// leaking it would expose an internal sentinel and, in SARIF, turn its colon
/// into a malformed path component. Valid UTF-8 escaped solely because it
/// begins with the sentinel is restored verbatim. Invalid native bytes remain
/// distinguishable without pretending they are a filesystem path.
#[must_use]
pub fn display_path(key: &str) -> String {
    let Some(hex) = key.strip_prefix(ESCAPED_PATH_PREFIX) else {
        return key.to_string();
    };
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let Some(high) = char::from(pair[0]).to_digit(16) else {
            return "<invalid stored path key>".to_string();
        };
        let Some(low) = char::from(pair[1]).to_digit(16) else {
            return "<invalid stored path key>".to_string();
        };
        bytes.push(u8::try_from((high << 4) | low).unwrap_or(u8::MAX));
    }
    if hex.len() % 2 != 0 {
        return "<invalid stored path key>".to_string();
    }
    String::from_utf8(bytes).unwrap_or_else(|_| format!("<non-UTF-8 path: {hex}>"))
}

#[cfg(test)]
mod tests;
