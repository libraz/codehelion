//! Ground-truth resolution: turning the regions collected while rendering
//! into the clone pairs, non-clones and known siblings of the label document,
//! each with its exact range in the generated file.

use std::collections::{BTreeMap, BTreeSet};

use crate::corpus::Error;
use crate::corpus::scan::Item;
use crate::corpus::spec::{ItemRef, KnownSiblingSpec, NonCloneSpec};
use crate::labels::{KnownSibling, LabelPair, NonClone};
use crate::schema::Fragment;

use super::{Line, PendingNonClone, PendingPair, RenderedVariant, is_statement, to_u32, to_usize};

/// Statement lines of a seed item, excluding the header line.
pub(super) fn count_statements(seed_lines: &[&str], item: &Item) -> u32 {
    let mut count = 0;
    for line_no in item.start_line.saturating_add(1)..=item.end_line {
        if let Some(text) = seed_lines.get(to_usize(line_no).saturating_sub(1)) {
            count += u32::from(is_statement(text.trim()));
        }
    }
    count
}

/// Output-line span (1-based, inclusive) of all lines whose provenance falls
/// inside the given seed range.
fn mapped_range(lines: &[Line], seed_start: u32, seed_end: u32) -> Option<(u32, u32)> {
    let mut first = None;
    let mut last = None;
    for (index, line) in lines.iter().enumerate() {
        if let Some(seed) = line.seed_line
            && seed >= seed_start
            && seed <= seed_end
        {
            let line_no = to_u32(index + 1);
            if first.is_none() {
                first = Some(line_no);
            }
            last = Some(line_no);
        }
    }
    first.zip(last)
}

/// Output-line span (1-based, inclusive) of the surviving lines a transplant
/// inserted.
fn transplant_range(lines: &[Line], id: usize) -> Option<(u32, u32)> {
    let mut first = None;
    let mut last = None;
    for (index, line) in lines.iter().enumerate() {
        if line.transplant == Some(id) {
            let line_no = to_u32(index + 1);
            if first.is_none() {
                first = Some(line_no);
            }
            last = Some(line_no);
        }
    }
    first.zip(last)
}

pub(super) fn resolve_pairs(
    pending: &[PendingPair],
    rendered: &[RenderedVariant],
    seed_file: &str,
) -> Result<Vec<LabelPair>, Error> {
    pending
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let variant = rendered
                .iter()
                .find(|rendered| rendered.file == pair.variant_file)
                .ok_or_else(|| Error::UnknownNonCloneRef {
                    reference: pair.variant_file.clone(),
                })?;
            let (start, end) = pair
                .transplant
                .map_or_else(
                    || mapped_range(&variant.lines, pair.seed_start, pair.seed_end),
                    |id| transplant_range(&variant.lines, id),
                )
                .ok_or_else(|| Error::EmptyRange {
                    variant: pair.variant_file.clone(),
                    item: pair.item_key.clone(),
                })?;
            Ok(LabelPair {
                id: format!("cp-{:03}", index + 1),
                clone_type: pair.clone_type,
                rule_id: None,
                fragments: vec![
                    Fragment {
                        file: seed_file.to_string(),
                        start_line: pair.seed_start,
                        end_line: pair.seed_end,
                        tokens: 0,
                    },
                    Fragment {
                        file: pair.variant_file.clone(),
                        start_line: start,
                        end_line: end,
                        tokens: 0,
                    },
                ],
            })
        })
        .collect()
}

pub(super) fn resolve_non_clones(
    specs: &[NonCloneSpec],
    by_key: &BTreeMap<&str, &Item>,
    rendered: &[RenderedVariant],
    seed_file: &str,
) -> Result<Vec<NonClone>, Error> {
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let function = by_key.get(spec.function.as_str()).copied().ok_or_else(|| {
                Error::UnknownNonCloneRef {
                    reference: spec.function.clone(),
                }
            })?;
            let counterpart_key = spec.counterpart.as_ref().unwrap_or(&spec.function);
            let counterpart = by_key
                .get(counterpart_key.as_str())
                .copied()
                .ok_or_else(|| Error::UnknownNonCloneRef {
                    reference: counterpart_key.clone(),
                })?;
            let variant = rendered
                .iter()
                .find(|rendered| rendered.file == spec.variant)
                .ok_or_else(|| Error::UnknownNonCloneRef {
                    reference: spec.variant.clone(),
                })?;
            let (start, end) =
                mapped_range(&variant.lines, counterpart.start_line, counterpart.end_line)
                    .ok_or_else(|| Error::EmptyRange {
                        variant: spec.variant.clone(),
                        item: counterpart_key.clone(),
                    })?;
            Ok(NonClone {
                id: format!("nc-{:03}", index + 1),
                reason: spec.reason.clone(),
                rule_id: None,
                fragments: vec![
                    Fragment {
                        file: seed_file.to_string(),
                        start_line: function.start_line,
                        end_line: function.end_line,
                        tokens: 0,
                    },
                    Fragment {
                        file: spec.variant.clone(),
                        start_line: start,
                        end_line: end,
                        tokens: 0,
                    },
                ],
            })
        })
        .collect()
}

/// Resolve known-sibling item references to exact generated line ranges.
///
/// Keeping this resolution in the generator makes the committed `labels.json`
/// a derived artifact just like every variant source. A line move in a seed
/// or a preceding edit therefore changes both the source and its label in one
/// deterministic regeneration.
pub(super) fn resolve_known_siblings(
    specs: &[KnownSiblingSpec],
    by_key: &BTreeMap<&str, &Item>,
    rendered: &[RenderedVariant],
    seed_file: &str,
) -> Result<Vec<KnownSibling>, Error> {
    let mut seen = BTreeSet::new();
    specs
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let references = [
                &spec.primary_fragments[0],
                &spec.primary_fragments[1],
                &spec.sibling,
            ];
            let mut item_refs = BTreeSet::new();
            for reference in references {
                let key = format!("{}:{}", reference.file, reference.item);
                if !item_refs.insert(key.clone()) {
                    return Err(Error::InvalidKnownSiblingRef { reference: key });
                }
            }
            let mut primary_keys = [
                format!(
                    "{}:{}",
                    spec.primary_fragments[0].file, spec.primary_fragments[0].item
                ),
                format!(
                    "{}:{}",
                    spec.primary_fragments[1].file, spec.primary_fragments[1].item
                ),
            ];
            primary_keys.sort();
            let relation = format!(
                "{}|{}|{}|{}:{}",
                spec.basis.as_str(),
                primary_keys[0],
                primary_keys[1],
                spec.sibling.file,
                spec.sibling.item
            );
            if !seen.insert(relation.clone()) {
                return Err(Error::DuplicateKnownSiblingRef {
                    reference: relation,
                });
            }
            let primary_fragments = spec
                .primary_fragments
                .iter()
                .map(|reference| resolve_known_sibling_ref(reference, by_key, rendered, seed_file))
                .collect::<Result<Vec<_>, _>>()?;
            let primary_fragments: [Fragment; 2] =
                primary_fragments
                    .try_into()
                    .map_err(|_| Error::InvalidKnownSiblingRef {
                        reference: relation.clone(),
                    })?;
            let sibling = resolve_known_sibling_ref(&spec.sibling, by_key, rendered, seed_file)?;
            Ok(KnownSibling {
                id: format!("ks-{:03}", index + 1),
                basis: spec.basis,
                primary_fragments,
                sibling,
            })
        })
        .collect()
}

/// Resolve one known-sibling file/item reference.
fn resolve_known_sibling_ref(
    reference: &ItemRef,
    by_key: &BTreeMap<&str, &Item>,
    rendered: &[RenderedVariant],
    seed_file: &str,
) -> Result<Fragment, Error> {
    let range = if reference.file == seed_file {
        let item = by_key
            .get(reference.item.as_str())
            .copied()
            .ok_or_else(|| Error::UnknownKnownSiblingRef {
                reference: format!("{}:{}", reference.file, reference.item),
            })?;
        (item.start_line, item.end_line)
    } else {
        let variant = rendered
            .iter()
            .find(|variant| variant.file == reference.file)
            .ok_or_else(|| Error::UnknownKnownSiblingRef {
                reference: format!("{}:{}", reference.file, reference.item),
            })?;
        variant
            .item_ranges
            .get(&reference.item)
            .copied()
            .ok_or_else(|| Error::UnknownKnownSiblingRef {
                reference: format!("{}:{}", reference.file, reference.item),
            })?
    };
    Ok(Fragment {
        file: reference.file.clone(),
        start_line: range.0,
        end_line: range.1,
        tokens: 0,
    })
}

/// Resolve the transplant-derived non-clones. Their ids continue the
/// numbering after the spec-level non-clones (`id_offset` entries).
pub(super) fn resolve_transplant_non_clones(
    pending: &[PendingNonClone],
    rendered: &[RenderedVariant],
    seed_file: &str,
    id_offset: usize,
) -> Result<Vec<NonClone>, Error> {
    pending
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let variant = rendered
                .iter()
                .find(|rendered| rendered.file == entry.variant_file)
                .ok_or_else(|| Error::UnknownNonCloneRef {
                    reference: entry.variant_file.clone(),
                })?;
            let (start, end) =
                transplant_range(&variant.lines, entry.transplant).ok_or_else(|| {
                    Error::EmptyRange {
                        variant: entry.variant_file.clone(),
                        item: entry.donor_key.clone(),
                    }
                })?;
            Ok(NonClone {
                id: format!("nc-{:03}", id_offset + index + 1),
                reason: entry.reason.clone(),
                rule_id: None,
                fragments: vec![
                    Fragment {
                        file: seed_file.to_string(),
                        start_line: entry.seed_start,
                        end_line: entry.seed_end,
                        tokens: 0,
                    },
                    Fragment {
                        file: entry.variant_file.clone(),
                        start_line: start,
                        end_line: end,
                        tokens: 0,
                    },
                ],
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
