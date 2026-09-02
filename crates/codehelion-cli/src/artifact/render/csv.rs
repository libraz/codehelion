//! CSV rendering of one artifact report.

use super::{
    artifact_import_kind_label, attribution_basis_field, attribution_column, optional_bytes,
    stated_bytes, summary_column,
};
use crate::artifact::correlation::AttributionBasis;
use crate::artifact::model::{
    ARTIFACT_CSV_HEADER, ArtifactReport, SourceMapResolutionStatus, column, report_assumptions,
};
use crate::artifact::{Context, Result, Write, csv};

#[allow(clippy::too_many_lines)] // CSV records intentionally remain together to preserve one fixed schema.
pub(in crate::artifact) fn render_csv(report: &ArtifactReport, out: &mut impl Write) -> Result<()> {
    writeln!(out, "{}", ARTIFACT_CSV_HEADER.join(","))?;
    let correlation = report.correlation.as_ref();
    let mut summary = artifact_csv_row("summary", report);
    summary[column::FINGERPRINT].clone_from(&report.fingerprint);
    // Every size category the classification states, written to the column
    // that carries it. Walking the same list the text and JSON renderings walk
    // is what keeps a category from being reachable in two formats out of
    // three, which is how one of them went missing before.
    for (category, bytes) in report.sizes.stated() {
        summary[summary_column(category)] = stated_bytes(bytes);
    }
    summary[column::SOURCE_RUN] =
        correlation.map_or_else(String::new, |value| value.source_run.to_string());
    summary[column::MAPPINGS] =
        correlation.map_or_else(String::new, |value| value.mappings.to_string());
    summary[column::MAPPED_SYMBOLS] =
        correlation.map_or_else(String::new, |value| value.mapped_symbols.to_string());
    summary[column::UNMAPPED_SYMBOLS] =
        correlation.map_or_else(String::new, |value| value.unmapped_symbols.to_string());
    summary[column::CODE_SECTION_BYTES] = report.code_section_bytes.to_string();
    summary[column::DATA_SEGMENT_BYTES] = report.data_segment_bytes.to_string();
    summary[column::CLONE_CONFIDENCE] = format!("{:?}", report.sizes.clone_confidence);
    summary[column::SAVINGS_CONFIDENCE] = format!("{:?}", report.sizes.savings_confidence);
    summary[column::ARTIFACT_SYMBOLS] = report.symbols.len().to_string();
    write_artifact_csv_row(out, &summary)?;
    if let Some(variant) = &report.build_variant {
        let mut row = artifact_csv_row("build-variant", report);
        row[column::FINGERPRINT].clone_from(&variant.fingerprint);
        row[column::NAME] = csv(&variant.manifest_path);
        write_artifact_csv_row(out, &row)?;
    }
    if let Some(containment) = &report.containment {
        let mut row = artifact_csv_row("containment", report);
        row[column::MAX_INPUT_BYTES] = containment.max_input_bytes.to_string();
        row[column::WORKER_TIMEOUT_SECONDS] = containment.worker_timeout_seconds.to_string();
        row[column::WORKER_MEMORY_LIMIT_BYTES] = containment.worker_memory_limit_bytes.to_string();
        row[column::MAX_DEBUG_DERIVED_ITEMS] = containment.max_debug_derived_items.to_string();
        write_artifact_csv_row(out, &row)?;
    }
    for member in &report.archive_members {
        let mut row = artifact_csv_row("archive-member", report);
        row[column::KIND] = member
            .format
            .map_or_else(|| "unknown".to_owned(), |format| format.to_string());
        row[column::FINGERPRINT].clone_from(&member.fingerprint);
        row[column::NAME] = csv(&member.name);
        // A thin member has neither, and an empty field is how this record
        // says so: a zero here would be a position and a length.
        row[column::OFFSET] = member
            .offset
            .map_or_else(String::new, |offset| offset.to_string());
        row[column::SIZE] = member
            .size
            .map_or_else(String::new, |size| size.to_string());
        row[column::DEAD_CODE_STATUS] = csv(member.parse_error.as_deref().unwrap_or("parsed"));
        write_artifact_csv_row(out, &row)?;
    }
    for map in &report.source_maps {
        let mut row = artifact_csv_row("source-map", report);
        row[column::SOURCE_MAP_URI] = csv(&map.uri);
        match &map.status {
            SourceMapResolutionStatus::Resolved {
                local_path,
                sources,
                ..
            } => {
                "resolved".clone_into(&mut row[column::KIND]);
                row[column::SOURCE_MAP_LOCAL_PATH] = csv(local_path);
                row[column::SOURCE_MAP_SOURCES] = csv(&sources.join(";"));
            }
            SourceMapResolutionStatus::Unavailable { reason } => {
                (*reason).clone_into(&mut row[column::KIND]);
            }
        }
        write_artifact_csv_row(out, &row)?;
    }
    for section in &report.section_details {
        let mut row = artifact_csv_row("section", report);
        row[column::KIND] = if section.executable {
            "executable".to_owned()
        } else {
            "non-executable".to_owned()
        };
        row[column::NAME] = csv(section.name.as_deref().unwrap_or(""));
        row[column::OFFSET] = section.offset.to_string();
        row[column::SIZE] = section.size.to_string();
        row[column::EXECUTABLE] = section.executable.to_string();
        write_artifact_csv_row(out, &row)?;
    }
    for import in &report.import_details {
        let mut row = artifact_csv_row("import", report);
        artifact_import_kind_label(import.kind).clone_into(&mut row[column::KIND]);
        row[column::NAME] = csv(import.name.as_deref().unwrap_or(""));
        row[column::MODULE] = csv(import.module.as_deref().unwrap_or(""));
        write_artifact_csv_row(out, &row)?;
    }
    for relocation in &report.relocation_details {
        let mut row = artifact_csv_row("relocation", report);
        row[column::KIND] = csv(&relocation.kind);
        row[column::NAME] = csv(relocation.target.as_deref().unwrap_or(""));
        row[column::OFFSET] = relocation.offset.to_string();
        row[column::SECTION] = relocation
            .section
            .map_or_else(String::new, |section| section.to_string());
        write_artifact_csv_row(out, &row)?;
    }
    for segment in &report.data_segment_details {
        let mut row = artifact_csv_row("data-segment", report);
        "exact-data".clone_into(&mut row[column::KIND]);
        row[column::FINGERPRINT].clone_from(&segment.fingerprint);
        row[column::OFFSET] = segment.offset.to_string();
        row[column::SIZE] = segment.size.to_string();
        row[column::SECTION] = segment
            .section
            .map_or_else(String::new, |section| section.to_string());
        write_artifact_csv_row(out, &row)?;
    }
    for (kind, groups) in [
        ("exact", &report.duplicate_groups.exact),
        ("normalized", &report.duplicate_groups.normalized),
        ("data", &report.duplicate_groups.data),
    ] {
        for group in groups {
            let mut row = artifact_csv_row("duplicate-group", report);
            kind.clone_into(&mut row[column::KIND]);
            row[column::FINGERPRINT] = group.fingerprint.to_string();
            row[column::DUPLICATED_BYTES] = group.duplicated_bytes.to_string();
            row[column::MEMBERS] = group.members.len().to_string();
            write_artifact_csv_row(out, &row)?;
            for member in &group.members {
                let mut row = artifact_csv_row("duplicate-member", report);
                kind.clone_into(&mut row[column::KIND]);
                row[column::FINGERPRINT] = member.symbol.to_string();
                row[column::OFFSET] = member.offset.to_string();
                row[column::SIZE] = member.size.to_string();
                write_artifact_csv_row(out, &row)?;
            }
        }
    }
    if let Some(dead_code) = &report.dead_code {
        let status = if dead_code.definitive {
            "definitive"
        } else {
            "candidate"
        };
        for symbol in &dead_code.symbols {
            let mut row = artifact_csv_row("dead-code", report);
            row[column::FINGERPRINT] = symbol.to_string();
            status.clone_into(&mut row[column::DEAD_CODE_STATUS]);
            write_artifact_csv_row(out, &row)?;
        }
    }
    if let Some(retained) = &report.retained_sizes {
        for item in retained {
            let mut row = artifact_csv_row("retained-size", report);
            row[column::FINGERPRINT] = item.symbol.to_string();
            row[column::RETAINED_BYTES] = item.retained_bytes.to_string();
            write_artifact_csv_row(out, &row)?;
        }
    }
    if let Some(correlation) = correlation {
        // Observed and line-proportional bytes occupy separate columns, so a
        // reader taking either one by position never receives the other kind
        // of number.
        for attribution in &correlation.clone_group_attributions {
            let mut row = artifact_csv_row("clone-group-attribution", report);
            "clone-group-attribution".clone_into(&mut row[column::KIND]);
            row[column::FINGERPRINT].clone_from(&attribution.clone_group_fingerprint);
            // Every byte count the attribution states, written to the column
            // that carries it. One absent value is spelled the same way as
            // every other on this record: an empty field, never a word in a
            // numeric column and never a zero.
            for (category, bytes) in attribution.stated() {
                row[attribution_column(category)] =
                    bytes.map_or_else(String::new, |bytes| bytes.to_string());
            }
            // The attributed count and the members it was drawn from each
            // carry the column that names them, so the ratio the text states
            // is recoverable here.
            row[column::MEMBERS] = attribution.members.to_string();
            row[column::ATTRIBUTED_NONCANONICAL_MEMBERS] =
                attribution.attributed_noncanonical_members.to_string();
            row[column::SOURCE_BUILD_VARIANT_FINGERPRINT]
                .clone_from(&attribution.source_build_variant_fingerprint);
            row[column::CLONE_CONFIDENCE] = format!("{:.3}", attribution.clone_confidence);
            // A group whose members were not all attributed carries no byte
            // total at all, so it names no evidence class either.
            row[column::ATTRIBUTION_BASIS] = attribution
                .duplicated_bytes
                .map(|_| AttributionBasis::Observed)
                .or_else(|| {
                    attribution
                        .estimated_duplicated_bytes
                        .map(|_| AttributionBasis::LineProportional)
                })
                .map_or_else(String::new, |basis| {
                    attribution_basis_field(basis).to_owned()
                });
            // Where the members sit and what they were charged are different
            // measurements, so the containing size takes a column of its own
            // rather than standing in for a duplicated-byte total.
            row[column::CONTAINING_SYMBOLS] = attribution.containing_symbols.to_string();
            write_artifact_csv_row(out, &row)?;
        }
        for unit in &correlation.multiply_emitted_units {
            let mut row = artifact_csv_row("multiply-emitted-unit", report);
            "multiply-emitted-unit".clone_into(&mut row[column::KIND]);
            row[column::FINGERPRINT].clone_from(&unit.source_fingerprint);
            if let Some(name) = &unit.name {
                row[column::NAME] = csv(name);
            }
            row[column::SIZE] = unit.observed_symbol_bytes.to_string();
            // The count takes the column that names it here and in the other
            // two formats. Writing it into the general symbol-count column as
            // well would give one number two spellings on one row.
            row[column::EMITTED_BODIES] = unit.emitted_bodies.to_string();
            row[column::SOURCE_BUILD_VARIANT_FINGERPRINT]
                .clone_from(&unit.source_build_variant_fingerprint);
            row[column::MAPPING_CONFIDENCE] = format!("{:?}", unit.mapping_confidence);
            write_artifact_csv_row(out, &row)?;
        }
        for estimate in &correlation.estimated_refactor_savings {
            let mut row = artifact_csv_row("clone-group-savings", report);
            "refactor-estimate".clone_into(&mut row[column::KIND]);
            row[column::FINGERPRINT].clone_from(&estimate.clone_group_fingerprint);
            let attributed = estimate.duplicated_bytes.to_string();
            if estimate.duplicated_bytes_basis.is_estimated() {
                row[column::ESTIMATED_DUPLICATED_BYTES] = attributed;
            } else {
                row[column::DUPLICATED_BYTES] = attributed;
            }
            attribution_basis_field(estimate.duplicated_bytes_basis)
                .clone_into(&mut row[column::ATTRIBUTION_BASIS]);
            row[column::ESTIMATED_REFACTOR_SAVINGS_BYTES] =
                estimate.estimated_refactor_savings_bytes.0.to_string();
            row[column::SOURCE_BUILD_VARIANT_FINGERPRINT]
                .clone_from(&estimate.source_build_variant_fingerprint);
            row[column::ARTIFACT_BUILD_VARIANT_FINGERPRINT]
                .clone_from(&estimate.artifact_build_variant_fingerprint);
            row[column::MAPPING_CONFIDENCE] = format!("{:?}", estimate.mapping_confidence);
            row[column::CLONE_CONFIDENCE] = format!("{:.3}", estimate.clone_confidence);
            row[column::MODEL_CONFIDENCE] = format!("{:?}", estimate.model_confidence);
            row[column::SAVINGS_CONFIDENCE] = format!("{:?}", estimate.savings_confidence);
            estimate
                .model_schema_version
                .clone_into(&mut row[column::MODEL_SCHEMA_VERSION]);
            row[column::ESTIMATE_ASSUMPTIONS_JSON] =
                csv(&serde_json::to_string(&estimate.assumptions)
                    .context("serializing CSV refactoring-estimate assumptions")?);
            write_artifact_csv_row(out, &row)?;
        }
        for origin in &correlation.generic_origins {
            let mut row = artifact_csv_row("generic-origin", report);
            "generic-origin".clone_into(&mut row[column::KIND]);
            row[column::FINGERPRINT].clone_from(&origin.origin_fingerprint);
            row[column::NAME] = csv(&origin.definition);
            row[column::SIZE] = origin.observed_symbol_bytes.to_string();
            row[column::DUPLICATED_BYTES] =
                origin.normalized_instruction_duplicated_bytes.to_string();
            row[column::RETAINED_BYTES] = optional_bytes(origin.retained_size_sum);
            row[column::ORIGIN_BUILD_VARIANT_FINGERPRINT]
                .clone_from(&origin.origin_build_variant_fingerprint);
            row[column::INSTANTIATIONS] = origin.instantiations.to_string();
            row[column::TRANSLATION_UNITS] = origin.translation_units.to_string();
            row[column::ARTIFACT_SYMBOLS] = origin.artifact_symbols.to_string();
            write_artifact_csv_row(out, &row)?;
            for specialization in &origin.specializations {
                let mut row = artifact_csv_row("generic-specialization", report);
                "generic-origin".clone_into(&mut row[column::KIND]);
                row[column::FINGERPRINT].clone_from(&origin.origin_fingerprint);
                row[column::NAME] = csv(&specialization.instantiation_key);
                row[column::SIZE] = specialization.observed_symbol_bytes.to_string();
                row[column::ORIGIN_BUILD_VARIANT_FINGERPRINT]
                    .clone_from(&origin.origin_build_variant_fingerprint);
                "1".clone_into(&mut row[column::INSTANTIATIONS]);
                row[column::TRANSLATION_UNITS] = specialization.translation_units.to_string();
                row[column::ARTIFACT_SYMBOLS] = specialization.artifact_symbols.to_string();
                write_artifact_csv_row(out, &row)?;
            }
        }
        for origin in &correlation.macro_origins {
            let mut row = artifact_csv_row("macro-origin", report);
            "macro-origin".clone_into(&mut row[column::KIND]);
            row[column::FINGERPRINT].clone_from(&origin.origin_fingerprint);
            row[column::NAME] = csv(&origin.definition_paths.join(";"));
            row[column::SIZE] = origin.observed_symbol_bytes.to_string();
            row[column::ORIGIN_BUILD_VARIANT_FINGERPRINT]
                .clone_from(&origin.origin_build_variant_fingerprint);
            // Symbol counts and definition paths are neither instantiations
            // nor translation units, and now say which they are.
            row[column::ARTIFACT_SYMBOLS] = origin.artifact_symbols.to_string();
            row[column::DEFINITION_PATH_COUNT] = origin.definition_paths.len().to_string();
            write_artifact_csv_row(out, &row)?;
        }
    }
    // The statements that qualify these numbers reach this format from the
    // same description the text and JSON renderings read.
    for assumption in report_assumptions(report) {
        let mut row = artifact_csv_row("assumption", report);
        assumption
            .scope
            .field()
            .clone_into(&mut row[column::ASSUMPTION_SCOPE]);
        row[column::ASSUMPTION] = csv(assumption.text);
        write_artifact_csv_row(out, &row)?;
    }
    Ok(())
}

/// Start one artifact CSV record with the fields every record carries.
fn artifact_csv_row(record_type: &str, report: &ArtifactReport) -> Vec<String> {
    let mut row = vec![String::new(); ARTIFACT_CSV_HEADER.len()];
    record_type.clone_into(&mut row[column::RECORD_TYPE]);
    row[column::PATH] = csv(&report.path);
    row[column::FORMAT] = report.format.to_string();
    row
}

fn write_artifact_csv_row(out: &mut impl Write, row: &[String]) -> Result<()> {
    debug_assert_eq!(row.len(), ARTIFACT_CSV_HEADER.len());
    writeln!(out, "{}", row.join(","))?;
    Ok(())
}
