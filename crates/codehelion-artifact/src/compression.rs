//! Compressed length of a complete artifact, measured with a named encoder.
//!
//! The figure describes the whole byte input and is never divided among
//! symbols: a compressor's output for one function depends on what precedes
//! it, so a per-symbol share would be an estimate rather than an observation.
//! Each value carries its encoder and settings, because another compressor at
//! the same nominal level produces a slightly different length.

use core::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A compression scheme whose output length can be measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAlgorithm {
    /// gzip container around DEFLATE.
    Gzip,
    /// Brotli stream.
    Brotli,
}

impl CompressionAlgorithm {
    /// The spelling reports and error messages use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Brotli => "brotli",
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

/// The compressed length of the complete byte input under one encoder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedSize {
    /// Scheme the length was measured with.
    pub algorithm: CompressionAlgorithm,
    /// Encoder settings, such as `level 9` or `quality 11, window 22`.
    pub parameters: String,
    /// Encoder implementation, such as `flate2 (miniz_oxide)`.
    pub encoder: String,
    /// Length of the complete compressed stream, container framing included.
    pub bytes: u64,
}

/// An encoder reported a write failure while measuring.
#[derive(Debug, Error)]
#[error("{algorithm} compression failed: {source}")]
pub struct CompressionError {
    /// Scheme whose encoder failed.
    pub algorithm: CompressionAlgorithm,
    /// The encoder's failure.
    #[source]
    pub source: std::io::Error,
}
