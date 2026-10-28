//! Compressed sizes of the whole artifact, and their before/after difference.

use codehelion_artifact::compression::CompressionAlgorithm;

use super::comparison::difference;
use crate::artifact::{ArtifactIr, Serialize};

/// The compressed length of the complete artifact under one encoder setting.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct CompressedSizeReport {
    pub(in crate::artifact) algorithm: CompressionAlgorithm,
    pub(in crate::artifact) parameters: String,
    pub(in crate::artifact) encoder: String,
    pub(in crate::artifact) bytes: u64,
}

/// One encoder setting measured on both artifacts of a comparison.
#[derive(Debug, Clone, Serialize)]
pub(in crate::artifact) struct CompressedDelta {
    pub(in crate::artifact) algorithm: CompressionAlgorithm,
    pub(in crate::artifact) parameters: String,
    pub(in crate::artifact) encoder: String,
    pub(in crate::artifact) before_bytes: u64,
    pub(in crate::artifact) after_bytes: u64,
    pub(in crate::artifact) delta_bytes: i128,
}

/// The sizes recorded with the analysis, in the order they were measured.
pub(in crate::artifact) fn compressed_sizes_of(artifact: &ArtifactIr) -> Vec<CompressedSizeReport> {
    artifact
        .compressed_sizes
        .iter()
        .map(|size| CompressedSizeReport {
            algorithm: size.algorithm,
            parameters: size.parameters.clone(),
            encoder: size.encoder.clone(),
            bytes: size.bytes,
        })
        .collect()
}

/// Settings measured on both sides, by algorithm.
///
/// A setting measured on one side only has no difference to state, and two
/// encoder versions are not the same setting, so both must agree on all
/// three of algorithm, parameters and encoder.
pub(in crate::artifact) fn compressed_deltas(
    before: &ArtifactIr,
    after: &ArtifactIr,
) -> Vec<CompressedDelta> {
    let mut deltas: Vec<CompressedDelta> = before
        .compressed_sizes
        .iter()
        .filter_map(|earlier| {
            let later = after.compressed_sizes.iter().find(|later| {
                later.algorithm == earlier.algorithm
                    && later.parameters == earlier.parameters
                    && later.encoder == earlier.encoder
            })?;
            Some(CompressedDelta {
                algorithm: earlier.algorithm,
                parameters: earlier.parameters.clone(),
                encoder: earlier.encoder.clone(),
                before_bytes: earlier.bytes,
                after_bytes: later.bytes,
                delta_bytes: difference(later.bytes, earlier.bytes),
            })
        })
        .collect();
    deltas.sort_by_key(|delta| delta.algorithm);
    deltas
}
