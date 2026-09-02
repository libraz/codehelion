//! Ratios, digest spellings, and the labels of the stored correlation enums.

use codehelion_store::BuildVariantFingerprint;

use crate::artifact::{
    ArtifactAnalysisSourceKind, ArtifactAnalysisUnmappedReason,
    ArtifactAnalysisUnmappedSourceReason,
};

/// The same read, for the one digest that names a build rather than code.
///
/// A separate entry point instead of a cast at each call, for the reason the
/// storage layer has one: the point of the type is that a reader can see which
/// digest is being treated as which.
pub(in crate::artifact) fn hex_build_variant(value: &str) -> Option<BuildVariantFingerprint> {
    hex_fingerprint(value).map(BuildVariantFingerprint::from_bytes)
}

pub(in crate::artifact) fn hex_fingerprint(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(bytes)
}

pub(super) const fn unmapped_reason_label(reason: ArtifactAnalysisUnmappedReason) -> &'static str {
    match reason {
        ArtifactAnalysisUnmappedReason::DebugInfoMissing => "debug_info_missing",
        ArtifactAnalysisUnmappedReason::DebugInfoUnreadable => "debug_info_unreadable",
        ArtifactAnalysisUnmappedReason::Stripped => "stripped",
        ArtifactAnalysisUnmappedReason::DemangleFailed => "demangle_failed",
        ArtifactAnalysisUnmappedReason::OutsideSourceScope => "outside_source_scope",
        ArtifactAnalysisUnmappedReason::EvidenceConflict => "evidence_conflict",
    }
}

pub(super) const fn unmapped_source_reason_label(
    reason: ArtifactAnalysisUnmappedSourceReason,
) -> &'static str {
    match reason {
        ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence => "no_artifact_evidence",
        ArtifactAnalysisUnmappedSourceReason::DeadCode => "dead_code",
        ArtifactAnalysisUnmappedSourceReason::InlinedAway => "inlined_away",
        ArtifactAnalysisUnmappedSourceReason::LtoAbsorbed => "lto_absorbed",
        ArtifactAnalysisUnmappedSourceReason::NotCompiledForVariant => "not_compiled_for_variant",
        ArtifactAnalysisUnmappedSourceReason::EvidenceConflict => "evidence_conflict",
    }
}

pub(in crate::artifact) const fn source_kind_order(kind: ArtifactAnalysisSourceKind) -> u8 {
    match kind {
        ArtifactAnalysisSourceKind::Unit => 0,
        ArtifactAnalysisSourceKind::Fragment => 1,
    }
}

pub(in crate::artifact) fn ratio(numerator: usize, denominator: usize) -> f64 {
    ratio_u64(
        u64::try_from(numerator).unwrap_or(u64::MAX),
        u64::try_from(denominator).unwrap_or(u64::MAX),
    )
}

pub(in crate::artifact) fn ratio_u64(numerator: u64, denominator: u64) -> f64 {
    ratio_u128(u128::from(numerator), u128::from(denominator))
}

pub(in crate::artifact) fn ratio_u128(numerator: u128, denominator: u128) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        const BASIS_POINTS_PER_UNIT: u128 = 10_000;
        let basis_points = numerator
            .saturating_mul(BASIS_POINTS_PER_UNIT)
            .checked_div(denominator)
            .unwrap_or(BASIS_POINTS_PER_UNIT)
            .min(BASIS_POINTS_PER_UNIT);
        let basis_points = u32::try_from(basis_points).unwrap_or(10_000);
        f64::from(basis_points) / 10_000.0
    }
}
