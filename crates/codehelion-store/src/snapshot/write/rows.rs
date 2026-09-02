//! Per-table row writes for one snapshot: what the run reported about itself,
//! the tree it read, its suppression policy, and its source units.

use crate::snapshot::variant::upsert_fingerprint;
use crate::snapshot::{
    FileRow, OptionalExtension, Snapshot, StagedSuppression, StoreError, SummaryRow,
    SuppressionRuleRow, Transaction, params,
};

/// Declare `component` at `version` for `run_id`, reusing the existing row
/// when the pair has been recorded before.
pub(super) fn record_detector_version(
    tx: &Transaction<'_>,
    run_id: i64,
    component: &str,
    version: &str,
) -> Result<(), StoreError> {
    tx.execute(
        "INSERT OR IGNORE INTO detector_version (component, version) VALUES (?1, ?2)",
        params![component, version],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO scan_run_detector_version (scan_run_id, detector_version_id)
         SELECT ?1, id FROM detector_version WHERE component = ?2 AND version = ?3",
        params![run_id, component, version],
    )?;
    Ok(())
}

/// Record what the run reported about itself: the source it read, the funnel
/// it narrowed through, and the rules that hid nothing.
#[allow(
    clippy::too_many_lines,
    reason = "the summary write keeps every persisted field and its SQL binding adjacent"
)]
pub(super) fn write_summary(
    tx: &Transaction<'_>,
    summary: &SummaryRow,
    run_id: i64,
) -> Result<(), StoreError> {
    let count = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT INTO run_summary
             (scan_run_id, analyzed_total, analyzed_rust, analyzed_c, analyzed_cpp,
              lines, tokens, lexer_diagnostics, unparsed_files, unparsed_tokens,
              excluded_generated, excluded_by_glob, excluded_too_large,
              excluded_binary, excluded_unreadable, excluded_symlinks,
              excluded_walk_errors,
              excluded_timed_out, excluded_skipped, guardrail_profile,
              guardrail_max_file_bytes, guardrail_parse_timeout_ms,
              guardrail_helper_timeout_ms, guardrail_posting_cap,
              guardrail_pair_budget, guardrail_sibling_candidate_budget,
              guardrail_sibling_per_group_cap, guardrail_sibling_total_cap,
              guardrail_signature_sibling_candidate_budget,
              guardrail_signature_sibling_per_group_cap,
              guardrail_signature_sibling_total_cap, guardrail_max_component, folded_runs,
              subsumed_runs, split_components, pair_budget_exhausted, baseline_digest,
              excluded_language, excluded_symlink_files, excluded_symlink_directories,
              guardrail_near_miss_delta, guardrail_near_miss_cap,
              guardrail_verification_budget, guardrail_max_alignment_cells,
              guardrail_signature_sibling_max_units_per_signature,
              common_signatures_skipped, largest_skipped_signature_units,
              excluded_oversized_metadata)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                 ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26,
                 ?27, ?28, ?29, ?30, ?31, ?32, ?33, ?34, ?35, ?36, ?37, ?38,
                 ?39, ?40, ?41, ?42, ?43, ?44, ?45, ?46, ?47, ?48)",
        params![
            run_id,
            count(summary.analyzed_files.total),
            count(summary.analyzed_files.rust),
            count(summary.analyzed_files.c),
            count(summary.analyzed_files.cpp),
            count(summary.lines),
            count(summary.tokens),
            count(summary.lexer_diagnostics),
            summary.unparsed.map(|row| count(row.files)),
            summary.unparsed.map(|row| count(row.tokens)),
            count(summary.excluded_generated),
            count(summary.excluded_by_glob),
            count(summary.excluded_too_large),
            count(summary.excluded_binary),
            count(summary.excluded_unreadable),
            count(summary.excluded_symlinks),
            count(summary.excluded_walk_errors),
            count(summary.excluded_timed_out),
            count(summary.excluded_skipped),
            summary.guardrails.as_ref().map(|row| &row.profile),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.max_file_bytes)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.parse_timeout_ms)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.helper_timeout_ms)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.posting_cap)),
            summary
                .guardrails
                .as_ref()
                .map(|row| count(row.pair_budget)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.sibling_candidate_budget.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.sibling_per_group_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.sibling_total_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_candidate_budget.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_per_group_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_total_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.max_component.map(count)),
            count(summary.folded_runs),
            count(summary.subsumed_runs),
            count(summary.split_components),
            summary.pair_budget_exhausted,
            summary.baseline_digest,
            count(summary.excluded_language),
            count(summary.excluded_symlink_files),
            count(summary.excluded_symlink_directories),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.near_miss_delta_bits.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.near_miss_cap.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.verification_budget.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.max_alignment_cells.map(count)),
            summary
                .guardrails
                .as_ref()
                .and_then(|row| row.signature_sibling_max_units_per_signature.map(count)),
            count(summary.common_signatures_skipped),
            count(summary.largest_skipped_signature_units),
            count(summary.excluded_oversized_metadata),
        ],
    )?;
    let mut insert_stage = tx.prepare_cached(
        "INSERT INTO run_funnel_stage (scan_run_id, position, name, passed)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut insert_drop = tx.prepare_cached(
        "INSERT INTO run_funnel_drop
             (scan_run_id, position, ordinal, cause, dropped)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for (position, stage) in summary.funnel.iter().enumerate() {
        let position = i64::try_from(position).unwrap_or(i64::MAX);
        insert_stage.execute(params![run_id, position, stage.name, count(stage.passed)])?;
        for (ordinal, drop) in stage.dropped.iter().enumerate() {
            insert_drop.execute(params![
                run_id,
                position,
                i64::try_from(ordinal).unwrap_or(i64::MAX),
                drop.cause,
                count(drop.count),
            ])?;
        }
    }
    drop(insert_drop);
    drop(insert_stage);
    let mut insert_unused_suppression = tx.prepare_cached(
        "INSERT INTO run_unused_suppression (scan_run_id, ordinal, scope, pattern)
         VALUES (?1, ?2, ?3, ?4)",
    )?;
    for (ordinal, rule) in summary.unused_suppressions.iter().enumerate() {
        insert_unused_suppression.execute(params![
            run_id,
            i64::try_from(ordinal).unwrap_or(i64::MAX),
            rule.scope,
            rule.pattern,
        ])?;
    }
    Ok(())
}

/// Record the tree the run read, one row per file.
pub(super) fn write_files(
    tx: &Transaction<'_>,
    files: &[FileRow],
    run_id: i64,
) -> Result<(), StoreError> {
    let mut insert = tx.prepare_cached(
        "INSERT INTO scanned_file
             (scan_run_id, relative_path, content_hash, language, byte_len)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    for file in files {
        insert.execute(params![
            run_id,
            file.relative_path,
            file.content_hash,
            file.language.name(),
            i64::try_from(file.byte_len).unwrap_or(i64::MAX),
        ])?;
    }
    Ok(())
}

/// Record the active suppression rules, reusing existing `(scope, pattern)`
/// rows so rules stay content-addressed across runs.
pub(super) fn write_suppressions(
    tx: &Transaction<'_>,
    rules: &[SuppressionRuleRow],
    activate: bool,
) -> Result<(Vec<i64>, Vec<StagedSuppression>), StoreError> {
    // A rule is active only while the current invocation supplied it. Keep
    // historic finding references intact, but make a removed rule visibly
    // inactive instead of leaving its first-seen state frozen forever.
    if activate {
        tx.execute("UPDATE suppression SET active = 0 WHERE active = 1", [])?;
    }
    let mut row_ids = Vec::with_capacity(rules.len());
    let mut staged = Vec::with_capacity(rules.len());
    for rule in rules {
        let existing: Option<i64> = tx
            .query_row(
                "SELECT id FROM suppression
                 WHERE scope = ?1 AND pattern = ?2",
                params![rule.scope, rule.pattern],
                |row| row.get(0),
            )
            .optional()?;
        let (id, created) = if let Some(id) = existing {
            if activate {
                tx.execute(
                    "UPDATE suppression SET reason = ?2, active = 1 WHERE id = ?1",
                    params![id, rule.reason],
                )?;
            }
            (id, false)
        } else {
            tx.execute(
                "INSERT INTO suppression (scope, pattern, reason, active)
                 VALUES (?1, ?2, ?3, ?4)",
                params![rule.scope, rule.pattern, rule.reason, activate],
            )?;
            (tx.last_insert_rowid(), true)
        };
        row_ids.push(id);
        staged.push(StagedSuppression {
            id,
            reason: rule.reason.clone(),
            created,
        });
    }
    Ok((row_ids, staged))
}

pub(super) fn write_units(
    tx: &Transaction<'_>,
    snapshot: &Snapshot<'_>,
    run_id: i64,
    variant_id: i64,
) -> Result<Vec<i64>, StoreError> {
    let mut unit_row_ids = Vec::with_capacity(snapshot.units.len());
    let mut insert = tx.prepare_cached(
        "INSERT INTO source_unit
             (scan_run_id, fingerprint_id, language, unit_kind, name,
              file_path, start_line, end_line, token_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )?;
    for unit in &snapshot.units {
        let fp_id = upsert_fingerprint(
            tx,
            "unit",
            unit.fingerprint.as_bytes(),
            snapshot,
            variant_id,
            unit.language,
        )?;
        insert.execute(params![
            run_id,
            fp_id,
            unit.language.name(),
            unit.kind.name(),
            unit.name,
            unit.file_path,
            unit.start_line,
            unit.end_line,
            i64::try_from(unit.token_count).unwrap_or(i64::MAX),
        ])?;
        unit_row_ids.push(tx.last_insert_rowid());
    }
    Ok(unit_row_ids)
}
