//! Compiler IR projection into source-anchored semantic evidence.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module exposes resolution helpers to semantic scan code"
)]

use codehelion_core::discovery::Language;
use codehelion_core::ir::ByteRange;
use codehelion_core::semantic::{
    ApiNormalization, ConstructObservation, DirectPropagation as CoreDirectPropagation,
    FallibleKind as CoreFallibleKind, OperationKind, OperationObservation, SemanticGraphError,
    SemanticSourceRange, normalize_registered_observations_with_ranges,
};
use codehelion_core::types::TypeTag;
use codehelion_helper::ir::{
    CallTarget, CompilerIr, DirectPropagation as HelperDirectPropagation,
    FallibleKind as HelperFallibleKind, SemanticConstructKind,
};

/// The types `ir` resolved inside `file`, at the bytes they were written at.
///
/// Anchored rather than summed: which unit a type belongs to is decided by the
/// crate that read the tree into units, and handing it a per-file total would
/// be attributing a type to a unit this side guessed at.
///
/// A category this build does not recognise, or one the helper could not
/// resolve, contributes nothing: an unresolved type is the compiler saying it
/// does not know, and two units full of those would otherwise agree perfectly
/// about nothing.
#[must_use]
pub(crate) fn resolved_types_for(ir: &CompilerIr, file: &str) -> Vec<(ByteRange, TypeTag)> {
    let symbols = ir
        .symbols
        .iter()
        .filter(|symbol| symbol.anchor.expansion.file == file)
        .filter_map(|symbol| {
            let index = usize::try_from(symbol.type_index?).ok()?;
            let tag = TypeTag::from_category(ir.types.get(index)?.category.name())?;
            let range = &symbol.anchor.expansion;
            Some((
                ByteRange {
                    start: usize::try_from(range.start_byte).ok()?,
                    end: usize::try_from(range.end_byte).ok()?,
                },
                tag,
            ))
        });
    let expressions = ir.expressions.iter().filter_map(|expression| {
        let index = usize::try_from(expression.type_index).ok()?;
        let tag = TypeTag::from_category(ir.types.get(index)?.category.name())?;
        let range = &expression.anchor.expansion;
        (range.file == file).then_some((
            ByteRange {
                start: usize::try_from(range.start_byte).ok()?,
                end: usize::try_from(range.end_byte).ok()?,
            },
            tag,
        ))
    });
    symbols.chain(expressions).collect()
}

/// The call targets `ir` resolved inside `file`, at their call-site bytes.
///
/// A dynamic target is kept as one canonical candidate-set key. Treating each
/// candidate as an independent call would make two overlapping dispatch sets
/// look like the same API; the helper's protocol says the set itself is the
/// fact it learned. Unresolved calls contribute no compiler evidence, so the
/// verifier can retain its Structural call-name comparison.
#[must_use]
pub(crate) fn resolved_api_for(ir: &CompilerIr, file: &str) -> Vec<(ByteRange, String)> {
    ir.calls
        .iter()
        .filter(|call| call.anchor.expansion.file == file)
        .filter_map(|call| {
            let range = &call.anchor.expansion;
            let target = match &call.target {
                CallTarget::Static { symbol } => format!("static:{symbol}"),
                CallTarget::Dynamic { candidates } if !candidates.is_empty() => {
                    let mut candidates = candidates.clone();
                    candidates.sort_unstable();
                    candidates.dedup();
                    format!("dynamic:{}", candidates.join("\u{1f}"))
                }
                CallTarget::Dynamic { .. } | CallTarget::Unresolved => return None,
            };
            Some((
                ByteRange {
                    start: usize::try_from(range.start_byte).ok()?,
                    end: usize::try_from(range.end_byte).ok()?,
                },
                call.api_name.clone().unwrap_or(target),
            ))
        })
        .collect()
}

/// Convert compiler facts into the core-owned restricted SOG input.
///
/// This is the only protocol-aware step: core receives source order, resolved
/// API names, and coarse type evidence, never a helper IR value.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn registered_sog_for(
    ir: &CompilerIr,
    file: &str,
    language: Language,
    build_variant_fingerprint: [u8; 32],
) -> Result<ApiNormalization, SemanticGraphError> {
    registered_sog_in_range(ir, file, language, build_variant_fingerprint, None)
}

/// Convert compiler facts from one syntactic unit into restricted SOG input.
///
/// A file may hold several unrelated pipelines. Restricting observations to a
/// parser-owned unit range keeps them from becoming one invented sequence;
/// `None` is retained only for callers that explicitly ask for whole-file
/// normalization.
pub(crate) fn registered_sog_in_range(
    ir: &CompilerIr,
    file: &str,
    language: Language,
    build_variant_fingerprint: [u8; 32],
    range: Option<ByteRange>,
) -> Result<ApiNormalization, SemanticGraphError> {
    let types = resolved_types_for(ir, file);
    let observations = resolved_api_for(ir, file)
        .into_iter()
        .filter(|(call_range, _)| range.is_none_or(|unit_range| unit_range.contains(call_range)))
        .filter_map(|(range, api_name)| {
            Some((
                OperationObservation {
                    source_offset: u64::try_from(range.start).ok()?,
                    api_name,
                    type_tag: types
                        .iter()
                        .filter(|(type_range, _)| type_range.contains(&range))
                        .min_by_key(|(type_range, _)| type_range.len())
                        .map(|(_, tag)| *tag)
                        // A call target's function type is not the type of the value
                        // the SOG operation consumes or produces. Keeping it would
                        // make Rust and C++ disagree merely because their compiler
                        // IR anchors a resolved call differently.
                        .filter(|tag| *tag != TypeTag::Callable),
                },
                SemanticSourceRange {
                    start: u64::try_from(range.start).ok()?,
                    end: u64::try_from(range.end).ok()?,
                },
            ))
        })
        .collect();
    let constructs = ir
        .semantic_constructs
        .iter()
        .filter(|construct| construct.anchor.expansion.file == file)
        .filter_map(|construct| {
            let construct_range = ByteRange {
                start: usize::try_from(construct.anchor.expansion.start_byte).ok()?,
                end: usize::try_from(construct.anchor.expansion.end_byte).ok()?,
            };
            range
                .is_none_or(|unit_range| unit_range.contains(&construct_range))
                .then_some((
                    ConstructObservation {
                        source_offset: u64::try_from(construct_range.start).ok()?,
                        kind: match construct.kind {
                            SemanticConstructKind::Source => OperationKind::Source,
                            SemanticConstructKind::Collect => OperationKind::Collect,
                            SemanticConstructKind::Reduce => OperationKind::Reduce,
                            SemanticConstructKind::PropagateError => OperationKind::PropagateError,
                            SemanticConstructKind::Validate => OperationKind::Validate,
                            SemanticConstructKind::AcquireResource => {
                                OperationKind::AcquireResource
                            }
                            SemanticConstructKind::ReleaseResource => {
                                OperationKind::ReleaseResource
                            }
                        },
                        fallible_kind: construct.fallible_kind.map(|kind| match kind {
                            HelperFallibleKind::Option => CoreFallibleKind::Option,
                            HelperFallibleKind::Result => CoreFallibleKind::Result,
                        }),
                        direct_propagation: construct.direct_propagation.map(|form| match form {
                            HelperDirectPropagation::ResultAdapter => {
                                CoreDirectPropagation::ResultAdapter
                            }
                            HelperDirectPropagation::OptionAdapter => {
                                CoreDirectPropagation::OptionAdapter
                            }
                        }),
                        resource_kind: construct.resource_kind.clone(),
                    },
                    SemanticSourceRange {
                        start: u64::try_from(construct_range.start).ok()?,
                        end: u64::try_from(construct_range.end).ok()?,
                    },
                ))
        })
        .collect();
    normalize_registered_observations_with_ranges(
        language,
        build_variant_fingerprint,
        observations,
        constructs,
    )
}
