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

use rusqlite::ToSql;
use rusqlite::types::{FromSql, FromSqlResult, ToSqlOutput, ValueRef};

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
