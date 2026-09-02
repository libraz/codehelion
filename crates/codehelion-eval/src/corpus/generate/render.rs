//! Variant rendering: copying seed items, applying substitution, transplants
//! and line edits, while recording each output line's provenance and the
//! labelled regions the resolution step later turns into label ranges.

use std::collections::{BTreeMap, BTreeSet};

use crate::corpus::Error;
use crate::corpus::lexer::substitute;
use crate::corpus::scan::{Item, brace_balance};
use crate::corpus::spec::{EditOp, ItemSpec, TransplantSpec, VariantSpec};
use crate::schema::CloneType;

use super::resolve::count_statements;
use super::{
    ChangeRate, GENERATED_MARKER, Line, PendingLabels, PendingNonClone, PendingPair, RenderContext,
    RenderedVariant, is_statement, to_u32, to_usize,
};

pub(super) fn render_variant(
    variant: &VariantSpec,
    ctx: &RenderContext<'_>,
    change_rates: &mut Vec<ChangeRate>,
    pending: &mut PendingLabels,
) -> Result<RenderedVariant, Error> {
    let mut lines = vec![
        Line {
            text: format!("// {}", variant.header_comment),
            seed_line: None,
            transplant: None,
        },
        Line {
            text: GENERATED_MARKER.to_string(),
            seed_line: None,
            transplant: None,
        },
    ];
    let mut seen = BTreeSet::new();
    let mut item_ranges = BTreeMap::new();
    for item_spec in &variant.items {
        if !seen.insert(item_spec.item.as_str()) {
            return Err(Error::DuplicateItem {
                key: item_spec.item.clone(),
            });
        }
        let item = ctx
            .by_key
            .get(item_spec.item.as_str())
            .copied()
            .filter(|item| !item.nested)
            .ok_or_else(|| Error::UnknownItem {
                variant: variant.file.clone(),
                item: item_spec.item.clone(),
            })?;
        let effective = item_spec.clone_type.unwrap_or(variant.clone_type);
        validate_item(effective, ctx.default_type, &variant.file, item_spec)?;

        lines.push(Line {
            text: String::new(),
            seed_line: None,
            transplant: None,
        });
        if item_spec.labelled {
            pending.pairs.push(PendingPair {
                variant_file: variant.file.clone(),
                clone_type: effective,
                item_key: item_spec.item.clone(),
                seed_start: item.start_line,
                seed_end: item.end_line,
                transplant: None,
            });
        }
        let (mut item_lines, changed) = render_item(item_spec, item, ctx, pending)?;
        let start = to_u32(lines.len().saturating_add(1));
        let item_line_count = to_u32(item_lines.len());
        let end = start.saturating_add(item_line_count.saturating_sub(1));
        item_ranges.insert(item_spec.item.clone(), (start, end));
        lines.append(&mut item_lines);

        if effective == CloneType::Type3 && (changed > 0 || item_spec.target_change_rate.is_some())
        {
            change_rates.push(ChangeRate {
                variant: variant.file.clone(),
                item: item_spec.item.clone(),
                target: item_spec.target_change_rate,
                changed_statements: changed,
                total_statements: count_statements(ctx.seed_lines, item),
            });
        }
    }
    Ok(RenderedVariant {
        file: variant.file.clone(),
        lines,
        item_ranges,
    })
}

fn validate_item(
    effective: CloneType,
    default_type: CloneType,
    variant: &str,
    item_spec: &ItemSpec,
) -> Result<(), Error> {
    if !matches!(
        effective,
        CloneType::Type1 | CloneType::Type2 | CloneType::Type3
    ) {
        return Err(Error::UnsupportedCloneType {
            variant: variant.to_string(),
        });
    }
    let disallowed = |reason: &str| {
        Err(Error::DisallowedEdit {
            variant: variant.to_string(),
            item: item_spec.item.clone(),
            reason: reason.to_string(),
        })
    };
    let has_substitution = !item_spec.rename.is_empty() || !item_spec.literals.is_empty();
    let has_statement_edit = item_spec.edits.iter().any(|edit| {
        matches!(
            edit,
            EditOp::InsertAfter { .. }
                | EditOp::InsertBefore { .. }
                | EditOp::Delete { .. }
                | EditOp::Replace { .. }
        )
    });
    if effective == CloneType::Type1 && has_substitution {
        return disallowed(
            "type-1 allows whitespace and comment changes only; `rename`/`literals` require type-2",
        );
    }
    if effective != CloneType::Type3 {
        if has_statement_edit {
            return disallowed("statement insertion, deletion or replacement requires type-3");
        }
        if !item_spec.transplants.is_empty() {
            return disallowed("transplanting a fragment inserts statements and requires type-3");
        }
        if item_spec.target_change_rate.is_some() {
            return disallowed("`target_change_rate` requires type-3");
        }
    }
    for transplant in &item_spec.transplants {
        validate_transplant(transplant, default_type, variant, &item_spec.item)?;
    }
    Ok(())
}

/// Validate one transplant's label declaration against the effective-type
/// rules: a labelled transplant is type-1 (verbatim only) or type-2, and
/// `labelled` and `non_clone` are mutually exclusive.
fn validate_transplant(
    transplant: &TransplantSpec,
    default_type: CloneType,
    variant: &str,
    item: &str,
) -> Result<(), Error> {
    let disallowed = |reason: String| {
        Err(Error::DisallowedEdit {
            variant: variant.to_string(),
            item: item.to_string(),
            reason,
        })
    };
    if transplant.labelled && transplant.non_clone.is_some() {
        return disallowed(format!(
            "transplant from `{}` cannot be both `labelled` and a `non_clone`",
            transplant.donor
        ));
    }
    if !transplant.labelled {
        return Ok(());
    }
    let effective = transplant.clone_type.unwrap_or(default_type);
    let has_substitution = !transplant.rename.is_empty() || !transplant.literals.is_empty();
    match effective {
        CloneType::Type1 if has_substitution => disallowed(format!(
            "a type-1 transplant from `{}` must be verbatim; `rename`/`literals` require type-2",
            transplant.donor
        )),
        CloneType::Type1 | CloneType::Type2 => Ok(()),
        _ => disallowed(format!(
            "a labelled transplant from `{}` must be type-1 or type-2",
            transplant.donor
        )),
    }
}

/// Render one item: copy its seed lines with provenance, apply substitution,
/// apply the transplants, then apply the line edits in spec order. Returns
/// the lines and the number of statement lines inserted or deleted.
fn render_item(
    item_spec: &ItemSpec,
    item: &Item,
    ctx: &RenderContext<'_>,
    pending: &mut PendingLabels,
) -> Result<(Vec<Line>, u32), Error> {
    let needs_substitution = !item_spec.rename.is_empty() || !item_spec.literals.is_empty();
    let mut lines = Vec::new();
    for line_no in item.start_line..=item.end_line {
        if let Some(text) = ctx.seed_lines.get(to_usize(line_no).saturating_sub(1)) {
            let text = if needs_substitution {
                substitute(text, &item_spec.rename, &item_spec.literals)
            } else {
                (*text).to_string()
            };
            lines.push(Line {
                text,
                seed_line: Some(line_no),
                transplant: None,
            });
        }
    }
    let mut changed = 0;
    for transplant in &item_spec.transplants {
        changed += apply_transplant(&mut lines, transplant, &item_spec.item, ctx, pending)?;
    }
    for edit in &item_spec.edits {
        changed += apply_edit(&mut lines, edit, ctx.variant_file, &item_spec.item)?;
    }
    Ok((lines, changed))
}

/// Apply one transplant: copy the donor fragment out of the seed, apply the
/// transplant's substitutions, insert the lines after the host anchor and
/// queue the declared label. Returns the number of statement lines inserted.
fn apply_transplant(
    lines: &mut Vec<Line>,
    transplant: &TransplantSpec,
    host_key: &str,
    ctx: &RenderContext<'_>,
    pending: &mut PendingLabels,
) -> Result<u32, Error> {
    let donor = ctx
        .by_key
        .get(transplant.donor.as_str())
        .copied()
        .ok_or_else(|| Error::UnknownItem {
            variant: ctx.variant_file.to_string(),
            item: transplant.donor.clone(),
        })?;
    let from = find_seed_anchor(ctx, donor, &transplant.from)?;
    let to = find_seed_anchor(ctx, donor, &transplant.to)?;
    if from > to {
        return Err(Error::DisallowedEdit {
            variant: ctx.variant_file.to_string(),
            item: transplant.donor.clone(),
            reason: format!(
                "fragment anchor `{}` lies below its `to` anchor `{}`",
                transplant.from, transplant.to
            ),
        });
    }
    let needs_substitution = !transplant.rename.is_empty() || !transplant.literals.is_empty();
    let mut fragment = Vec::new();
    let mut balance = 0;
    let mut statements = 0;
    for line_no in from..=to {
        if let Some(text) = ctx.seed_lines.get(to_usize(line_no).saturating_sub(1)) {
            balance += brace_balance(text);
            let text = if needs_substitution {
                substitute(text, &transplant.rename, &transplant.literals)
            } else {
                (*text).to_string()
            };
            statements += u32::from(is_statement(text.trim()));
            fragment.push(text);
        }
    }
    if balance != 0 {
        return Err(Error::DisallowedEdit {
            variant: ctx.variant_file.to_string(),
            item: transplant.donor.clone(),
            reason: format!(
                "fragment `{}` .. `{}` is not brace-balanced",
                transplant.from, transplant.to
            ),
        });
    }
    let index = find_anchor(lines, &transplant.after, ctx.variant_file, host_key)?;
    let id = pending.next_transplant;
    pending.next_transplant += 1;
    for (offset, text) in fragment.into_iter().enumerate() {
        lines.insert(
            index + 1 + offset,
            Line {
                text,
                seed_line: None,
                transplant: Some(id),
            },
        );
    }
    if transplant.labelled {
        pending.pairs.push(PendingPair {
            variant_file: ctx.variant_file.to_string(),
            clone_type: transplant.clone_type.unwrap_or(ctx.default_type),
            item_key: transplant.donor.clone(),
            seed_start: from,
            seed_end: to,
            transplant: Some(id),
        });
    }
    if let Some(reason) = &transplant.non_clone {
        pending.non_clones.push(PendingNonClone {
            variant_file: ctx.variant_file.to_string(),
            donor_key: transplant.donor.clone(),
            reason: reason.clone(),
            seed_start: from,
            seed_end: to,
            transplant: id,
        });
    }
    Ok(statements)
}

/// Resolve an anchor against a donor item's seed lines, returning the
/// matching absolute seed line (1-based). Like edit anchors, the anchor is
/// compared against each line's whitespace-trimmed text and must match
/// exactly one line of the item.
fn find_seed_anchor(ctx: &RenderContext<'_>, donor: &Item, anchor: &str) -> Result<u32, Error> {
    let mut found = None;
    for line_no in donor.start_line..=donor.end_line {
        let Some(text) = ctx.seed_lines.get(to_usize(line_no).saturating_sub(1)) else {
            continue;
        };
        if text.trim() == anchor {
            if found.is_some() {
                return Err(Error::AmbiguousAnchor {
                    variant: ctx.variant_file.to_string(),
                    item: donor.key.clone(),
                    anchor: anchor.to_string(),
                });
            }
            found = Some(line_no);
        }
    }
    found.ok_or_else(|| Error::AnchorNotFound {
        variant: ctx.variant_file.to_string(),
        item: donor.key.clone(),
        anchor: anchor.to_string(),
    })
}

/// Apply one edit, returning the number of statement lines it inserted or
/// deleted.
fn apply_edit(
    lines: &mut Vec<Line>,
    edit: &EditOp,
    variant: &str,
    item: &str,
) -> Result<u32, Error> {
    let inserted = |text: String| Line {
        text,
        seed_line: None,
        transplant: None,
    };
    match edit {
        EditOp::CommentBefore { text } => {
            lines.insert(0, inserted(format!("// {text}")));
            Ok(0)
        }
        EditOp::CommentAfter { anchor, text } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            let indent = leading_whitespace(&lines[index].text).to_string();
            lines.insert(index + 1, inserted(format!("{indent}// {text}")));
            Ok(0)
        }
        EditOp::BlankAfter { anchor } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            lines.insert(index + 1, inserted(String::new()));
            Ok(0)
        }
        EditOp::RemoveBlankAfter { anchor } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            if lines
                .get(index + 1)
                .is_some_and(|line| line.text.trim().is_empty())
            {
                lines.remove(index + 1);
                Ok(0)
            } else {
                Err(Error::DisallowedEdit {
                    variant: variant.to_string(),
                    item: item.to_string(),
                    reason: format!("no blank line follows anchor `{anchor}`"),
                })
            }
        }
        EditOp::Reindent { unit } => {
            reindent(lines, *unit, variant, item)?;
            Ok(0)
        }
        EditOp::InsertAfter { anchor, lines: new } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            Ok(insert_lines(lines, index + 1, new))
        }
        EditOp::InsertBefore { anchor, lines: new } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            Ok(insert_lines(lines, index, new))
        }
        EditOp::Delete { anchor } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            let removed = lines.remove(index);
            Ok(u32::from(is_statement(removed.text.trim())))
        }
        EditOp::Replace { anchor, lines: new } => {
            let index = find_anchor(lines, anchor, variant, item)?;
            let removed = lines.remove(index);
            // The statement that went and the statements that arrived both
            // count. A replacement is one edit to write and two changes to
            // the sequence, and a rate that counted it once would understate
            // how far the variant had moved.
            Ok(u32::from(is_statement(removed.text.trim()))
                .saturating_add(insert_lines(lines, index, new)))
        }
    }
}

fn insert_lines(lines: &mut Vec<Line>, at: usize, new: &[String]) -> u32 {
    let mut statements = 0;
    for (offset, text) in new.iter().enumerate() {
        statements += u32::from(is_statement(text.trim()));
        lines.insert(
            at + offset,
            Line {
                text: text.clone(),
                seed_line: None,
                transplant: None,
            },
        );
    }
    statements
}

fn find_anchor(lines: &[Line], anchor: &str, variant: &str, item: &str) -> Result<usize, Error> {
    let mut found = None;
    for (index, line) in lines.iter().enumerate() {
        if line.text.trim() == anchor {
            if found.is_some() {
                return Err(Error::AmbiguousAnchor {
                    variant: variant.to_string(),
                    item: item.to_string(),
                    anchor: anchor.to_string(),
                });
            }
            found = Some(index);
        }
    }
    found.ok_or_else(|| Error::AnchorNotFound {
        variant: variant.to_string(),
        item: item.to_string(),
        anchor: anchor.to_string(),
    })
}

fn leading_whitespace(text: &str) -> &str {
    &text[..text.len() - text.trim_start().len()]
}

fn reindent(lines: &mut [Line], unit: u8, variant: &str, item: &str) -> Result<(), Error> {
    for line in lines.iter_mut() {
        let trimmed = line.text.trim_start();
        if trimmed.is_empty() {
            continue;
        }
        let indent = leading_whitespace(&line.text);
        if indent.chars().any(|c| c != ' ') || !indent.len().is_multiple_of(4) {
            return Err(Error::DisallowedEdit {
                variant: variant.to_string(),
                item: item.to_string(),
                reason: format!(
                    "cannot reindent `{trimmed}`: indentation is not a multiple of 4 spaces"
                ),
            });
        }
        let new_indent = " ".repeat((indent.len() / 4) * usize::from(unit));
        line.text = format!("{new_indent}{trimmed}");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
