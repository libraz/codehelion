//! Rendering of one before/after artifact comparison.

use crate::artifact::model::{
    ArtifactComparisonReport, AssumptionScope, COMPARE_CSV_HEADER, compare_column,
    comparison_assumptions, pairs_both_artifacts,
};
use crate::artifact::{Result, Write, csv, optional_f64};

pub(in crate::artifact) fn render_compare_csv(
    report: &ArtifactComparisonReport,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "{}", COMPARE_CSV_HEADER.join(","))?;
    write_compare_csv_row(out, &compare_csv_row(report, "summary"))?;
    for delta in &report.symbol_deltas {
        let mut row = compare_csv_row(report, "symbol-delta");
        delta.kind.clone_into(&mut row[compare_column::CHANGE_KIND]);
        row[compare_column::NAME] = csv(delta.name.as_deref().unwrap_or(""));
        row[compare_column::FINGERPRINT].clone_from(&delta.fingerprint);
        row[compare_column::SYMBOL_SIZE_DELTA_BYTES] = delta.size_delta_bytes.to_string();
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
    out: &mut impl Write,
) -> Result<()> {
    writeln!(
        out,
        "before: {} ({})",
        report.before.path, report.before.format
    )?;
    render_selected_architecture("before", &report.before, out)?;
    writeln!(
        out,
        "after: {} ({})",
        report.after.path, report.after.format
    )?;
    render_selected_architecture("after", &report.after, out)?;
    if let Some(variant) = &report.before.build_variant {
        writeln!(
            out,
            "before build variant: {} (digest {})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(variant) = &report.after.build_variant {
        writeln!(
            out,
            "after build variant: {} (digest {})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(containment) = &report.containment {
        writeln!(
            out,
            "untrusted containment: input {} bytes, worker timeout {}s, worker memory {} bytes",
            containment.max_input_bytes,
            containment.worker_timeout_seconds,
            containment.worker_memory_limit_bytes,
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
            "calibration: scan {} group {} — estimated {} bytes, verified {} bytes, absolute error {} bytes, relative error {}",
            calibration.source_run,
            calibration.clone_group_fingerprint,
            calibration.estimated_refactor_savings_bytes.0,
            calibration.verified_savings_bytes.0,
            calibration.absolute_error_bytes,
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
    writeln!(
        out,
        "symbols: {} added, {} removed, {} named modified",
        report.symbol_changes.added,
        report.symbol_changes.removed,
        report.symbol_changes.modified_named_symbols,
    )?;
    render_symbol_deltas(&report.symbol_deltas, out)?;
    for delta in &report.duplicate_group_deltas {
        writeln!(
            out,
            "  duplicate {} {} {:+} bytes, {:+} members",
            delta.kind, delta.fingerprint, delta.duplicated_bytes_delta, delta.members_delta,
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

/// Changed symbols, one line each while a name identifies them.
///
/// A stripped artifact leaves every changed symbol nameless, and one line per
/// content fingerprint then says nothing a reader can act on: the before and
/// after of one symbol carry different fingerprints, so no two of those lines
/// can be paired. They become one line stating how many there are and how to
/// get names into the next comparison. The report keeps every entry.
fn render_symbol_deltas(deltas: &[super::model::SymbolDelta], out: &mut impl Write) -> Result<()> {
    let mut nameless = 0_usize;
    for delta in deltas {
        match delta.name.as_deref() {
            Some(name) => writeln!(
                out,
                "  {} {} {} {:+} bytes",
                delta.kind, name, delta.fingerprint, delta.size_delta_bytes
            )?,
            // A change found on both sides is identified by the one
            // fingerprint they share, so it stays actionable unnamed.
            None if pairs_both_artifacts(delta.kind) => writeln!(
                out,
                "  {} {} {:+} bytes",
                delta.kind, delta.fingerprint, delta.size_delta_bytes
            )?,
            None => nameless += 1,
        }
    }
    if nameless > 0 {
        writeln!(
            out,
            "  note: {nameless} of {} listed symbol changes have no name; their before and after cannot be paired — compare artifacts that keep their symbol names (an unstripped symbol table or the WASM name section)",
            deltas.len()
        )?;
    }
    Ok(())
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
    format!("{delta:+} bytes ({direction})")
}

fn render_selected_architecture(
    label: &str,
    artifact: &super::model::ComparisonArtifact,
    out: &mut impl Write,
) -> Result<()> {
    if let Some(architecture) = &artifact.architecture {
        writeln!(out, "{label} architecture: {architecture}")?;
    }
    if !artifact.skipped_architectures.is_empty() {
        writeln!(
            out,
            "{label} skipped architectures: {}",
            artifact.skipped_architectures.join(", ")
        )?;
    }
    Ok(())
}
