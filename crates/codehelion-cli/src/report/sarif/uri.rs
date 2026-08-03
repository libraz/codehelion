//! URI escaping and timestamp normalization for SARIF.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the private implementation module exposes helpers to its parent module"
)]

/// Percent-encode a path as a URI reference relative to [`SRCROOT`].
///
/// Everything outside the unreserved set is escaped, so a path containing
/// spaces or non-ASCII characters still yields a valid URI. Backslashes become
/// separators: a URI path is separated by `/` on every platform.
pub(crate) fn uri_reference(path: &str) -> String {
    let mut uri = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                uri.push(char::from(byte));
            }
            b'\\' => uri.push('/'),
            _ => {
                const HEX: [u8; 16] = *b"0123456789ABCDEF";
                uri.push('%');
                uri.push(char::from(HEX[usize::from(byte >> 4)]));
                uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    uri
}

/// Absolute `file:` URI for the scan root, with the trailing slash that marks
/// it as a directory the result URIs are resolved against.
pub(crate) fn root_uri(root: &str) -> String {
    let normalized = root.replace('\\', "/");
    let bytes = normalized.as_bytes();
    let encoded = if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        format!(
            "{}:{}",
            char::from(bytes[0]),
            uri_reference(&normalized[2..])
        )
    } else {
        uri_reference(&normalized)
    };
    let mut uri = String::from("file://");
    if !encoded.starts_with('/') {
        uri.push('/');
    }
    uri.push_str(&encoded);
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

/// Restate an RFC 3339 UTC timestamp with the millisecond precision SARIF
/// specifies (`yyyy-MM-ddTHH:mm:ss.sssZ`). A value in another shape is passed
/// through unchanged rather than mangled.
pub(super) fn millisecond_timestamp(value: &str) -> String {
    let Some(rest) = value.strip_suffix('Z') else {
        return value.to_string();
    };
    let (seconds, fraction) = rest.split_once('.').unwrap_or((rest, ""));
    if !seconds.contains('T') {
        return value.to_string();
    }
    let mut millis: String = fraction.chars().take(3).collect();
    while millis.len() < 3 {
        millis.push('0');
    }
    format!("{seconds}.{millis}Z")
}
