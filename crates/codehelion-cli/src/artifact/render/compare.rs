//! Rendering of one before/after artifact comparison.

use codehelion_artifact::ownership::Ownership;

use std::collections::HashMap;

use super::{
    counted, display_name, noun, render_fact_lines, render_omitted, signed_counted,
    write_fact_columns,
};
use crate::artifact::model::{
    ArtifactComparisonReport, AssumptionScope, COMPARE_CSV_HEADER, COMPARISON_FACTS,
    OwnershipDeltaReport, StemDelta, SymbolDelta, compare_column, comparison_assumptions,
    ownership_label, pairs_both_artifacts, symbol_change,
};
use crate::artifact::{Result, Write, csv, optional_f64};

pub(in crate::artifact) fn render_compare_csv(
    report: &ArtifactComparisonReport,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "{}", COMPARE_CSV_HEADER.join(","))?;
    let mut summary = compare_csv_row(report, "summary");
    write_fact_columns(COMPARISON_FACTS, report, COMPARE_CSV_HEADER, &mut summary)?;
    summary[compare_column::OUTSIDE_SYMBOLS_DELTA_BYTES] = report
        .ownership_deltas
        .outside_symbols_delta_bytes
        .to_string();
    write_compare_csv_row(out, &summary)?;
    for delta in &report.compressed_deltas {
        let mut row = compare_csv_row(report, "compressed-delta");
        row[compare_column::COMPRESSION_ALGORITHM] = delta.algorithm.to_string();
        row[compare_column::COMPRESSION_PARAMETERS] = csv(&delta.parameters);
        row[compare_column::COMPRESSION_ENCODER] = csv(&delta.encoder);
        row[compare_column::BEFORE_COMPRESSED_BYTES] = delta.before_bytes.to_string();
        row[compare_column::AFTER_COMPRESSED_BYTES] = delta.after_bytes.to_string();
        row[compare_column::COMPRESSED_DELTA_BYTES] = delta.delta_bytes.to_string();
        write_compare_csv_row(out, &row)?;
    }
    for delta in &report.symbol_deltas {
        let row = symbol_delta_row(report, delta);
        write_compare_csv_row(out, &row)?;
    }
    for owner in &report.ownership_deltas.owners {
        let mut row = compare_csv_row(report, "owner-delta");
        ownership_label(owner.ownership).clone_into(&mut row[compare_column::CHANGE_KIND]);
        row[compare_column::NAME] = csv(&owner.key);
        row[compare_column::SYMBOL_SIZE_DELTA_BYTES] = owner.delta_bytes.to_string();
        write_compare_csv_row(out, &row)?;
    }
    for delta in &report.stem_deltas {
        let mut row = compare_csv_row(report, "stem-delta");
        row[compare_column::NAME_STEM] = csv(&delta.stem);
        row[compare_column::STEM_PARAMETERIZED] = delta.parameterized.to_string();
        row[compare_column::OWNER] = csv(&delta.owner);
        ownership_label(delta.ownership).clone_into(&mut row[compare_column::OWNERSHIP]);
        row[compare_column::BEFORE_BODIES] = delta.before_bodies.to_string();
        row[compare_column::AFTER_BODIES] = delta.after_bodies.to_string();
        row[compare_column::SYMBOL_SIZE_DELTA_BYTES] = delta.delta_bytes.to_string();
        write_compare_csv_row(out, &row)?;
    }
    for delta in &report.duplicate_group_deltas {
        let mut row = compare_csv_row(report, "duplicate-group-delta");
        delta.kind.clone_into(&mut row[compare_column::CHANGE_KIND]);
        row[compare_column::FINGERPRINT].clone_from(&delta.fingerprint);
        row[compare_column::DUPLICATED_BYTES_DELTA] = delta.duplicated_bytes_delta.to_string();
        row[compare_column::MEMBERS_DELTA] = delta.members_delta.to_string();
        write_compare_csv_row(out, &row)?;
    }
    if let Some(containment) = &report.containment {
        let mut row = compare_csv_row(report, "containment");
        row[compare_column::MAX_INPUT_BYTES] = containment.max_input_bytes.to_string();
        row[compare_column::WORKER_TIMEOUT_SECONDS] =
            containment.worker_timeout_seconds.to_string();
        row[compare_column::WORKER_MEMORY_LIMIT_BYTES] =
            containment.worker_memory_limit_bytes.to_string();
        write_compare_csv_row(out, &row)?;
    }
    if let Some(calibration) = &report.calibration {
        let mut row = compare_csv_row(report, "calibration");
        row[compare_column::ESTIMATED_REFACTOR_SAVINGS_BYTES] =
            calibration.estimated_refactor_savings_bytes.0.to_string();
        row[compare_column::VERIFIED_SAVINGS_BYTES] =
            calibration.verified_savings_bytes.0.to_string();
        row[compare_column::SOURCE_RUN] = calibration.source_run.to_string();
        row[compare_column::CLONE_GROUP_FINGERPRINT]
            .clone_from(&calibration.clone_group_fingerprint);
        row[compare_column::ABSOLUTE_ERROR_BYTES] = calibration.absolute_error_bytes.to_string();
        row[compare_column::RELATIVE_ERROR] = optional_f64(calibration.relative_error);
        row[compare_column::ARTIFACT_ANALYSIS_ID] = calibration.artifact_analysis_id.to_string();
        row[compare_column::MATCHING_ANALYSES] = calibration.matching_analyses.to_string();
        calibration_record_label(calibration.already_recorded)
            .clone_into(&mut row[compare_column::CALIBRATION_RECORD]);
        write_compare_csv_row(out, &row)?;
    }
    // The build-condition warning keeps its own record, and the remaining
    // statements arrive as assumption records, so each is written once.
    for assumption in comparison_assumptions(report) {
        let record_type = if assumption.scope == AssumptionScope::BuildVariant {
            "build-variant-warning"
        } else {
            "assumption"
        };
        let mut row = compare_csv_row(report, record_type);
        if assumption.scope == AssumptionScope::BuildVariant {
            row[compare_column::WARNING] = csv(assumption.text);
        } else {
            assumption
                .scope
                .field()
                .clone_into(&mut row[compare_column::ASSUMPTION_SCOPE]);
            row[compare_column::ASSUMPTION] = csv(assumption.text);
        }
        write_compare_csv_row(out, &row)?;
    }
    Ok(())
}

/// The CSV record for one changed symbol.
fn symbol_delta_row(report: &ArtifactComparisonReport, delta: &SymbolDelta) -> Vec<String> {
    let mut row = compare_csv_row(report, "symbol-delta");
    delta.kind.clone_into(&mut row[compare_column::CHANGE_KIND]);
    row[compare_column::NAME] = csv(delta.name.as_deref().unwrap_or(""));
    row[compare_column::FINGERPRINT].clone_from(&delta.fingerprint);
    row[compare_column::SYMBOL_SIZE_DELTA_BYTES] = delta.size_delta_bytes.to_string();
    row[compare_column::OWNER] = csv(&delta.owner);
    ownership_label(delta.ownership).clone_into(&mut row[compare_column::OWNERSHIP]);
    if let Some(counterpart) = &delta.counterpart {
        row[compare_column::COUNTERPART_FINGERPRINT].clone_from(counterpart);
    }
    row
}

fn compare_csv_row(report: &ArtifactComparisonReport, record_type: &str) -> Vec<String> {
    let mut row = vec![String::new(); COMPARE_CSV_HEADER.len()];
    record_type.clone_into(&mut row[compare_column::RECORD_TYPE]);
    row[compare_column::BEFORE_PATH] = csv(&report.before.path);
    row[compare_column::AFTER_PATH] = csv(&report.after.path);
    row[compare_column::BEFORE_FORMAT] = report.before.format.to_string();
    row[compare_column::AFTER_FORMAT] = report.after.format.to_string();
    row[compare_column::BEFORE_FINGERPRINT].clone_from(&report.before.fingerprint);
    row[compare_column::AFTER_FINGERPRINT].clone_from(&report.after.fingerprint);
    row[compare_column::OBSERVED_SIZE_REDUCTION_BYTES] =
        report.observed_size_reduction_bytes.0.to_string();
    row[compare_column::DUPLICATED_CODE_DELTA_BYTES] =
        report.duplicated_code_delta_bytes.to_string();
    row[compare_column::DUPLICATED_DATA_DELTA_BYTES] = report
        .duplicated_data_delta_bytes
        .map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
    // An observed difference is attributable to code or to data only when both
    // sides publish both totals, exactly as the single-artifact report does.
    row[compare_column::BEFORE_CODE_SECTION_BYTES] = report.before.code_section_bytes.to_string();
    row[compare_column::AFTER_CODE_SECTION_BYTES] = report.after.code_section_bytes.to_string();
    row[compare_column::CODE_SECTION_DELTA_BYTES] = report.code_section_delta_bytes.to_string();
    row[compare_column::BEFORE_DATA_SEGMENT_BYTES] = report.before.data_segment_bytes.to_string();
    row[compare_column::AFTER_DATA_SEGMENT_BYTES] = report.after.data_segment_bytes.to_string();
    row[compare_column::DATA_SEGMENT_DELTA_BYTES] = report.data_segment_delta_bytes.to_string();
    row
}

/// How one recorded measurement reached the stored calibration row.
const fn calibration_record_label(already_recorded: bool) -> &'static str {
    if already_recorded {
        "already recorded"
    } else {
        "newly recorded"
    }
}

fn write_compare_csv_row(out: &mut impl Write, row: &[String]) -> Result<()> {
    debug_assert_eq!(row.len(), COMPARE_CSV_HEADER.len());
    writeln!(out, "{}", row.join(",")).map_err(Into::into)
}

#[allow(clippy::too_many_lines)] // The comparison order is its public text contract.
pub(in crate::artifact) fn render_compare_text(
    report: &ArtifactComparisonReport,
    verbose: bool,
    out: &mut impl Write,
) -> Result<()> {
    render_fact_lines(COMPARISON_FACTS, report, out)?;
    if let Some(containment) = &report.containment {
        writeln!(
            out,
            "untrusted containment: input {}, worker timeout {}s, worker memory {}",
            counted(containment.max_input_bytes, "byte", "bytes"),
            containment.worker_timeout_seconds,
            counted(containment.worker_memory_limit_bytes, "byte", "bytes"),
        )?;
    }
    // Every statement comes from one description of this comparison, and the
    // build-condition warning takes the line kept for it rather than being
    // repeated among the assumptions below.
    let assumptions = comparison_assumptions(report);
    for warning in assumptions
        .iter()
        .filter(|assumption| assumption.scope == AssumptionScope::BuildVariant)
    {
        writeln!(out, "build variant warning: {}", warning.text)?;
    }
    writeln!(
        out,
        "observed size: {}",
        signed_bytes(
            report.observed_size_reduction_bytes.0.saturating_neg(),
            "smaller",
            "larger"
        )
    )?;
    if let Some(calibration) = &report.calibration {
        writeln!(
            out,
            "calibration: scan {} group {} — estimated {}, verified {}, absolute error {}, relative error {}",
            calibration.source_run,
            calibration.clone_group_fingerprint,
            counted(
                calibration.estimated_refactor_savings_bytes.0,
                "byte",
                "bytes"
            ),
            counted(calibration.verified_savings_bytes.0, "byte", "bytes"),
            counted(calibration.absolute_error_bytes, "byte", "bytes"),
            calibration
                .relative_error
                .map_or_else(|| "unavailable".to_owned(), |value| format!("{value:.4}")),
        )?;
        // Which saved analysis the estimate came from, and whether taking the
        // same measurement again refreshed a row that was already on file.
        writeln!(
            out,
            "  measured against analysis {} of {} matching, {}",
            calibration.artifact_analysis_id,
            calibration.matching_analyses,
            calibration_record_label(calibration.already_recorded),
        )?;
    }
    writeln!(
        out,
        "duplicated code: {}",
        signed_bytes(
            report.duplicated_code_delta_bytes,
            "less duplicated",
            "more duplicated"
        )
    )?;
    writeln!(
        out,
        "duplicated data: {}",
        report.duplicated_data_delta_bytes.map_or_else(
            || "unavailable".to_owned(),
            |value| signed_bytes(value, "less duplicated", "more duplicated")
        )
    )?;
    // Whether an artifact grew in code or in data is the first question a
    // size difference raises, and both sides carry both totals.
    writeln!(
        out,
        "code section bytes: {} before, {} after, {}",
        report.before.code_section_bytes,
        report.after.code_section_bytes,
        signed_bytes(report.code_section_delta_bytes, "smaller", "larger")
    )?;
    writeln!(
        out,
        "data segment bytes: {} before, {} after, {}",
        report.before.data_segment_bytes,
        report.after.data_segment_bytes,
        signed_bytes(report.data_segment_delta_bytes, "smaller", "larger")
    )?;
    for delta in &report.compressed_deltas {
        writeln!(
            out,
            "compressed bytes ({}, {}, {}): {} before, {} after, {}",
            delta.algorithm,
            delta.parameters,
            delta.encoder,
            delta.before_bytes,
            delta.after_bytes,
            signed_bytes(delta.delta_bytes, "smaller", "larger")
        )?;
    }
    render_ownership_deltas(&report.ownership_deltas, out)?;
    render_stem_deltas(&report.stem_deltas, out)?;
    if !report.symbol_deltas.is_empty() {
        writeln!(out, "symbol changes:")?;
    }
    render_symbol_deltas(&report.symbol_deltas, verbose, out)?;
    if !report.duplicate_group_deltas.is_empty() {
        writeln!(out, "duplicate group changes:")?;
    }
    for delta in &report.duplicate_group_deltas {
        writeln!(
            out,
            "  {} {} {}, {}",
            delta.kind,
            delta.fingerprint,
            signed_counted(delta.duplicated_bytes_delta, "byte", "bytes"),
            signed_counted(delta.members_delta, "member", "members"),
        )?;
    }
    for assumption in assumptions
        .iter()
        .filter(|assumption| assumption.scope != AssumptionScope::BuildVariant)
    {
        writeln!(out, "assumption: {}", assumption.text)?;
    }
    Ok(())
}

/// One rendered line of the symbol changes list, with its sort keys.
struct DeltaLine<'a> {
    magnitude: u128,
    fingerprint: &'a str,
    text: String,
}

/// Changed symbols, one line each while a name identifies them, largest first
/// and capped at [`LISTED_SYMBOL_CHANGES`] lines.
///
/// A removed and an added symbol that name each other as counterparts are one
/// `replaced` line carrying the net change; the report keeps both entries.
///
/// A stripped artifact leaves every changed symbol nameless, and one line per
/// content fingerprint then says nothing a reader can act on: the before and
/// after of one symbol carry different fingerprints, so no two of those lines
/// can be paired. They become one line stating how many there are and how to
/// get names into the next comparison. The report keeps every entry.
fn render_symbol_deltas(deltas: &[SymbolDelta], verbose: bool, out: &mut impl Write) -> Result<()> {
    let added_by_name: HashMap<&str, &SymbolDelta> = deltas
        .iter()
        .filter(|delta| delta.kind == symbol_change::ADDED && delta.counterpart.is_some())
        .filter_map(|delta| Some((delta.name.as_deref()?, delta)))
        .collect();
    let mut lines = Vec::new();
    let mut nameless = 0_usize;
    for delta in deltas {
        let size = delta.size_delta_bytes;
        match delta.name.as_deref() {
            Some(name) => {
                // The added half of a replacement is shown on the removed
                // half's line.
                if delta.kind == symbol_change::ADDED && delta.counterpart.is_some() {
                    continue;
                }
                let shown = display_name(Some(name), verbose);
                let partner = if delta.kind == symbol_change::REMOVED && delta.counterpart.is_some()
                {
                    added_by_name.get(name).copied()
                } else {
                    None
                };
                if let Some(added) = partner {
                    let net = size + added.size_delta_bytes;
                    lines.push(DeltaLine {
                        magnitude: net.unsigned_abs(),
                        fingerprint: &added.fingerprint,
                        text: format!(
                            "  replaced {shown} {} -> {} {}",
                            delta.fingerprint,
                            added.fingerprint,
                            signed_counted(net, "byte", "bytes")
                        ),
                    });
                } else {
                    lines.push(DeltaLine {
                        magnitude: size.unsigned_abs(),
                        fingerprint: &delta.fingerprint,
                        text: format!(
                            "  {} {shown} {} {}",
                            delta.kind,
                            delta.fingerprint,
                            signed_counted(size, "byte", "bytes")
                        ),
                    });
                }
            }
            // A change found on both sides is identified by the one
            // fingerprint they share, so it stays actionable unnamed.
            None if pairs_both_artifacts(delta.kind) => lines.push(DeltaLine {
                magnitude: size.unsigned_abs(),
                fingerprint: &delta.fingerprint,
                text: format!(
                    "  {} {} {}",
                    delta.kind,
                    delta.fingerprint,
                    signed_counted(size, "byte", "bytes")
                ),
            }),
            None => nameless += 1,
        }
    }
    lines.sort_by(|left, right| {
        right
            .magnitude
            .cmp(&left.magnitude)
            .then_with(|| left.fingerprint.cmp(right.fingerprint))
    });
    for line in lines.iter().take(LISTED_SYMBOL_CHANGES) {
        writeln!(out, "{}", line.text)?;
    }
    render_omitted(
        lines.len(),
        LISTED_SYMBOL_CHANGES,
        "symbol change",
        "symbol changes",
        "  ",
        out,
    )?;
    if nameless > 0 {
        let total = deltas.len();
        let (subject, possessive) = if nameless == 1 {
            (
                format!(
                    "1 of {total} recorded symbol {}",
                    noun(total, "change", "changes")
                ),
                "has no name; its",
            )
        } else {
            (
                format!("{nameless} of {total} recorded symbol changes"),
                "have no name; their",
            )
        };
        writeln!(
            out,
            "  note: {subject} {possessive} before and after cannot be paired — compare artifacts that keep their symbol names (an unstripped symbol table or the WASM name section)"
        )?;
    }
    Ok(())
}

/// Symbol change lines listed in text; JSON and CSV carry every entry.
const LISTED_SYMBOL_CHANGES: usize = 20;
/// Owners listed in text; JSON carries every one.
const LISTED_OWNERS: usize = 10;

/// The class split of the symbol deltas, the owners that moved most, and the
/// part of the code delta no symbol covers.
fn render_ownership_deltas(deltas: &OwnershipDeltaReport, out: &mut impl Write) -> Result<()> {
    let classes: Vec<String> = deltas
        .classes
        .iter()
        .map(|class| {
            format!(
                "{} {}",
                ownership_label(class.ownership),
                signed_counted(class.delta_bytes, "byte", "bytes")
            )
        })
        .collect();
    writeln!(out, "ownership delta: {}", classes.join(", "))?;
    // The unnamed class has one key, which the class line already states.
    let owners: Vec<_> = deltas
        .owners
        .iter()
        .filter(|owner| owner.ownership != Ownership::Unnamed)
        .collect();
    for owner in owners.iter().take(LISTED_OWNERS) {
        writeln!(
            out,
            "  {} ({}): {}",
            owner.key,
            ownership_label(owner.ownership),
            signed_counted(owner.delta_bytes, "byte", "bytes")
        )?;
    }
    render_omitted(owners.len(), LISTED_OWNERS, "owner", "owners", "  ", out)?;
    writeln!(
        out,
        "  outside symbols: {}",
        signed_counted(deltas.outside_symbols_delta_bytes, "byte", "bytes")
    )?;
    Ok(())
}

/// The stems whose bodies changed in number, with the bytes they moved.
/// Nothing is written while there are none.
fn render_stem_deltas(deltas: &[StemDelta], out: &mut impl Write) -> Result<()> {
    if deltas.is_empty() {
        return Ok(());
    }
    writeln!(out, "stem delta:")?;
    for delta in deltas.iter().take(LISTED_OWNERS) {
        writeln!(
            out,
            "  {} ({}): {} -> {}, {}",
            delta.stem,
            ownership_label(delta.ownership),
            delta.before_bodies,
            counted(delta.after_bodies, "body", "bodies"),
            signed_counted(delta.delta_bytes, "byte", "bytes")
        )?;
    }
    render_omitted(deltas.len(), LISTED_OWNERS, "stem", "stems", "  ", out)
}

/// One byte difference written so its sign cannot be read backwards: the
/// number always counts the change from before to after, and a word states
/// which direction that is. Adjacent lines otherwise mix a reduction with a
/// delta and invert the meaning of `+` between them.
fn signed_bytes(delta: i128, decreased: &str, increased: &str) -> String {
    let direction = match delta.signum() {
        1 => increased,
        -1 => decreased,
        _ => "no change",
    };
    format!("{} ({direction})", signed_counted(delta, "byte", "bytes"))
}
