//! Compressed length of a complete artifact, measured with a named encoder.
//!
//! The figure describes the whole byte input and is never divided among
//! symbols: a compressor's output for one function depends on what precedes
//! it, so a per-symbol share would be an estimate rather than an observation.
//! Each value carries its encoder and settings, because another compressor at
//! the same nominal level produces a slightly different length.

use core::fmt;
use std::io::{self, Write};

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
    pub source: io::Error,
}

const GZIP_LEVEL: u32 = 9;
const BROTLI_QUALITY: i32 = 11;
const BROTLI_WINDOW: i32 = 22;

/// A `Write` sink that only counts the bytes it is given.
#[derive(Default)]
struct CountingSink {
    bytes: u64,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(buf.len()).unwrap_or(u64::MAX));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn gzip_into<W: Write>(bytes: &[u8], sink: W) -> io::Result<W> {
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .write(sink, flate2::Compression::new(GZIP_LEVEL));
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn brotli_into<W: Write>(bytes: &[u8], sink: &mut W) -> io::Result<()> {
    let mut params = brotli::enc::BrotliEncoderInitParams();
    params.quality = BROTLI_QUALITY;
    params.lgwin = BROTLI_WINDOW;
    params.size_hint = bytes.len();
    brotli::BrotliCompress(&mut &bytes[..], sink, &params).map(|_| ())
}

/// Measures the compressed length of `bytes` under each requested algorithm.
///
/// Algorithms are deduplicated and reported in `Ord` order. Nothing is
/// buffered: the encoders write into a counting sink.
///
/// # Errors
///
/// Returns the failing algorithm and the encoder's I/O error.
pub fn compressed_sizes(
    bytes: &[u8],
    algorithms: &[CompressionAlgorithm],
) -> Result<Vec<CompressedSize>, CompressionError> {
    let mut ordered = algorithms.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    ordered
        .into_iter()
        .map(|algorithm| {
            let fail = |source| CompressionError { algorithm, source };
            let (parameters, encoder, length) = match algorithm {
                CompressionAlgorithm::Gzip => {
                    let sink = gzip_into(bytes, CountingSink::default()).map_err(fail)?;
                    ("level 9", "flate2 (miniz_oxide)", sink.bytes)
                }
                CompressionAlgorithm::Brotli => {
                    let mut sink = CountingSink::default();
                    brotli_into(bytes, &mut sink).map_err(fail)?;
                    ("quality 11, window 22", "brotli (rust)", sink.bytes)
                }
            };
            Ok(CompressedSize {
                algorithm,
                parameters: parameters.to_owned(),
                encoder: encoder.to_owned(),
                bytes: length,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::io::Read;

    use super::*;

    const BOTH: [CompressionAlgorithm; 2] =
        [CompressionAlgorithm::Gzip, CompressionAlgorithm::Brotli];

    /// Repetitive but varied bytes, deterministic.
    fn sample() -> Vec<u8> {
        (0u32..6000)
            .map(|i| u8::try_from((i % 37) * 3 + (i / 211) % 5).unwrap_or(0))
            .collect()
    }

    fn gzip_stream(bytes: &[u8]) -> Vec<u8> {
        gzip_into(bytes, Vec::new()).unwrap()
    }

    fn brotli_stream(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        brotli_into(bytes, &mut out).unwrap();
        out
    }

    fn length_of(stream: &[u8]) -> u64 {
        u64::try_from(stream.len()).unwrap()
    }

    fn measured(bytes: &[u8], algorithm: CompressionAlgorithm) -> CompressedSize {
        compressed_sizes(bytes, &[algorithm]).unwrap().remove(0)
    }

    #[test]
    fn sink_length_equals_the_vec_stream_length() {
        let input = sample();
        assert_eq!(
            measured(&input, CompressionAlgorithm::Gzip).bytes,
            length_of(&gzip_stream(&input))
        );
        assert_eq!(
            measured(&input, CompressionAlgorithm::Brotli).bytes,
            length_of(&brotli_stream(&input))
        );
    }

    #[test]
    fn streams_decode_back_to_the_input() {
        let input = sample();
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(&gzip_stream(&input)[..])
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, input);
        decoded.clear();
        brotli::Decompressor::new(&brotli_stream(&input)[..], 4096)
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn measuring_twice_gives_the_same_value() {
        let input = sample();
        assert_eq!(
            compressed_sizes(&input, &BOTH).unwrap(),
            compressed_sizes(&input, &BOTH).unwrap()
        );
    }

    #[test]
    fn empty_input_matches_the_vec_stream_length() {
        assert_eq!(
            measured(&[], CompressionAlgorithm::Gzip).bytes,
            length_of(&gzip_stream(&[]))
        );
        assert_eq!(
            measured(&[], CompressionAlgorithm::Brotli).bytes,
            length_of(&brotli_stream(&[]))
        );
    }

    #[test]
    fn algorithms_are_deduplicated_and_ordered() {
        let sizes = compressed_sizes(
            b"abc",
            &[
                CompressionAlgorithm::Brotli,
                CompressionAlgorithm::Gzip,
                CompressionAlgorithm::Gzip,
            ],
        )
        .unwrap();
        let order: Vec<_> = sizes.iter().map(|size| size.algorithm).collect();
        assert_eq!(order, BOTH);
        assert_eq!(
            compressed_sizes(b"abc", &[]).unwrap(),
            Vec::<CompressedSize>::new()
        );
    }

    #[test]
    fn gzip_header_has_no_mtime_and_no_file_name() {
        let stream = gzip_stream(&sample());
        assert_eq!(stream[3] & 0x08, 0, "FNAME flag set");
        assert_eq!(stream[4..8], [0, 0, 0, 0]);
    }

    #[test]
    fn parameters_and_encoder_are_named() {
        let sizes = compressed_sizes(b"abc", &BOTH).unwrap();
        assert_eq!(
            (sizes[0].parameters.as_str(), sizes[0].encoder.as_str()),
            ("level 9", "flate2 (miniz_oxide)")
        );
        assert_eq!(
            (sizes[1].parameters.as_str(), sizes[1].encoder.as_str()),
            ("quality 11, window 22", "brotli (rust)")
        );
    }
}
