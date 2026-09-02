//! Stored identities that are not identities of any code.
//!
//! Almost every 128-bit digest this crate stores names a piece of code: a
//! unit, a fragment, a clone group, an artifact symbol. The build variant is
//! the one that does not. It names the configuration those identities were
//! minted under, and what it settles is which of them are comparable with each
//! other at all.
//!
//! Stored beside them as bare bytes, it was indistinguishable from them: a row
//! carrying a clone group's identity and two variant references has three
//! fields of one type, and passing them in the wrong order compiles. This is
//! the type that stops that.
//!
//! Reading one back from the hex a caller wrote it as is the same subject, so
//! the two widths that resolve to a 128-bit identity are decoded here: the
//! 32-digit stable ID, and the 64-digit build digest of which only the leading
//! half is the reference.

use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlResult, ToSqlOutput, ValueRef};

use crate::StoreError;

/// Reference to the build configuration a stored identity was minted under.
///
/// Deliberately not convertible to or from the code identities beside it: the
/// only ways in and out are [`Self::from_bytes`] and [`Self::as_bytes`], and
/// both are spelled out at every call so a reader can see which digest is
/// being treated as which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BuildVariantFingerprint([u8; 16]);

impl BuildVariantFingerprint {
    /// Read a variant reference from the bytes that carry it.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The reference's raw bytes, as the database column spells it.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl FromSql for BuildVariantFingerprint {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        let bytes: [u8; 16] = <[u8; 16] as FromSql>::column_result(value)?;
        Ok(Self(bytes))
    }
}

impl ToSql for BuildVariantFingerprint {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::from(self.0.as_slice()))
    }
}

/// Hex digits of a stable ID: the whole 128-bit value.
const STABLE_ID_DIGITS: usize = 32;

/// Hex digits of a stored build-variant digest, of which only the leading
/// 128 bits are the reference.
const BUILD_VARIANT_DIGEST_DIGITS: usize = 64;

/// Parse a 32-digit hex identifier into its 16 bytes.
pub(crate) fn parse_hex_id(hex: &str) -> Result<[u8; 16], StoreError> {
    decode_leading_fingerprint(hex, STABLE_ID_DIGITS)
}

/// Reduce the 32-byte build-variant digest stored by `build_variant` to the
/// 16-byte content-fingerprint reference used by source/artifact mappings.
///
/// The database records a full BLAKE3 digest for variant lookup, while mapping
/// rows use the project's standard 128-bit fingerprint width. Taking the
/// leading bytes preserves a deterministic reference without confusing this
/// representation with one of the stable IDs parsed by [`parse_hex_id`].
pub(crate) fn parse_build_variant_reference(
    hex: &str,
) -> Result<BuildVariantFingerprint, StoreError> {
    decode_leading_fingerprint(hex, BUILD_VARIANT_DIGEST_DIGITS)
        .map(BuildVariantFingerprint::from_bytes)
}

/// Decode the leading 16 bytes of an identifier written as exactly `digits`
/// hex digits.
///
/// Both widths resolve to one 128-bit value, and both report the whole input
/// as malformed when any part of it is not that, so a caller only chooses the
/// width it accepts.
fn decode_leading_fingerprint(hex: &str, digits: usize) -> Result<[u8; 16], StoreError> {
    let malformed = || StoreError::MalformedId { id: hex.to_owned() };
    if hex.len() != digits || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut out = [0_u8; 16];
    for (index, chunk) in hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .take(out.len())
        .enumerate()
    {
        let pair = core::str::from_utf8(chunk).map_err(|_| malformed())?;
        out[index] = u8::from_str_radix(pair, 16).map_err(|_| malformed())?;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_parse_and_reject_malformed_input() {
        let parsed = parse_hex_id("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(parsed[0], 0);
        assert_eq!(parsed[15], 0x0f);
        assert!(parse_hex_id("").is_err());
        assert!(parse_hex_id("zz0102030405060708090a0b0c0d0e0f").is_err());
        assert!(parse_hex_id("00010203").is_err());
    }

    #[test]
    fn build_variant_references_keep_the_first_128_bits_of_the_full_digest() {
        let parsed = parse_build_variant_reference(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        assert_eq!(
            parsed.as_bytes(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(parse_build_variant_reference("00010203").is_err());
    }
}
