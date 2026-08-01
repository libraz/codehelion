//! Human-readable and CSV artifact report rendering.

use super::correlation::RefactorSavingsAssumption;
use super::model::{ArtifactComparisonReport, ArtifactReport, SourceMapResolutionStatus};
use super::{
    ARTIFACT_CSV_COLUMNS, Context, EstimatedRefactorSavingsBytes, Result, VerifiedSavingsBytes,
    Write, csv, metrics, optional_f64,
};

#[allow(clippy::too_many_lines)] // The report order is its public text contract.
pub(super) fn render_text(
    report: &ArtifactReport,
    verbose: bool,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "artifact: {}", report.path)?;
    writeln!(out, "format: {}", report.format)?;
    writeln!(out, "fingerprint: {}", report.fingerprint)?;
    if let Some(variant) = &report.build_variant {
        writeln!(
            out,
            "build variant: {} ({})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    writeln!(out, "observed bytes: {}", report.observed_bytes)?;
    writeln!(out, "code section bytes: {}", report.code_section_bytes)?;
    writeln!(out, "data segment bytes: {}", report.data_segment_bytes)?;
    writeln!(out, "sections: {}", report.sections)?;
    if !report.section_details.is_empty() {
        writeln!(out, "section sizes:")?;
        for section in &report.section_details {
            writeln!(
                out,
                "  {}: offset {}, {} bytes{}",
                section.name.as_deref().unwrap_or("<unnamed>"),
                section.offset,
                section.size,
                if section.executable {
                    " (executable)"
                } else {
                    ""
                }
            )?;
        }
    }
    writeln!(out, "imports: {}", report.imports)?;
    writeln!(out, "symbols: {}", report.symbols.len())?;
    writeln!(out, "entry points: {}", report.entry_points)?;
    writeln!(out, "calls: {}", report.calls)?;
    writeln!(out, "relocations: {}", report.relocations)?;
    writeln!(out, "source mappings: {}", report.source_mappings)?;
    if !report.archive_members.is_empty() {
        let failed = report
            .archive_members
            .iter()
            .filter(|member| member.parse_error.is_some())
            .count();
        writeln!(
            out,
            "archive members: {} parsed, {failed} unavailable",
            report.archive_members.len().saturating_sub(failed)
        )?;
        for member in report
            .archive_members
            .iter()
            .filter(|member| member.parse_error.is_some())
        {
            writeln!(
                out,
                "  {}: {}",
                member.name,
                member.parse_error.as_deref().unwrap_or_default()
            )?;
        }
    }
    if !report.source_maps.is_empty() {
        let resolved = report
            .source_maps
            .iter()
            .filter(|map| matches!(&map.status, SourceMapResolutionStatus::Resolved { .. }))
            .count();
        writeln!(
            out,
            "source maps: {resolved} resolved, {} unavailable",
            report.source_maps.len().saturating_sub(resolved)
        )?;
    }
    if let Some(correlation) = &report.correlation {
        writeln!(
            out,
            "source correlation: scan {}: {} mappings, {}/{} mapped symbols ({:.1}%), {} / {} mapped symbol bytes ({:.1}%), {} unmapped symbols ({} bytes)",
            correlation.source_run,
            correlation.mappings,
            correlation.mapped_symbols,
            correlation.artifact_symbols,
            correlation.mapping_coverage * 100.0,
            correlation.mapped_symbol_bytes,
            report.symbols.iter().map(|symbol| symbol.size).sum::<u64>(),
            correlation.mapped_symbol_bytes_ratio * 100.0,
            correlation.unmapped_symbols,
            correlation.unmapped_symbol_bytes,
        )?;
        if !correlation.unmapped_symbol_reasons.is_empty() {
            writeln!(out, "unmapped symbol reasons:")?;
            for (reason, count) in &correlation.unmapped_symbol_reasons {
                writeln!(out, "  {reason}: {count}")?;
            }
        }
        writeln!(
            out,
            "source identities: {}, {} without artifact evidence",
            correlation.source_entities, correlation.unmapped_sources
        )?;
        if !correlation.unmapped_source_reasons.is_empty() {
            writeln!(out, "unmapped source reasons:")?;
            for (reason, count) in &correlation.unmapped_source_reasons {
                writeln!(out, "  {reason}: {count}")?;
            }
        }
        if !correlation.clone_group_attributions.is_empty() {
            writeln!(
                out,
                "clone group byte attributions (observed, not savings):"
            )?;
            for attribution in &correlation.clone_group_attributions {
                writeln!(
                    out,
                    "  {} ({}): {} / {} noncanonical members attributed, duplicated bytes: {}",
                    attribution.clone_group_fingerprint,
                    attribution.source_build_variant_fingerprint,
                    attribution.attributed_noncanonical_members,
                    attribution.members.saturating_sub(1),
                    optional_bytes(attribution.duplicated_bytes),
                )?;
            }
        }
        if !correlation.estimated_refactor_savings.is_empty() {
            writeln!(out, "clone group refactoring estimates (not guaranteed):")?;
            for estimate in &correlation.estimated_refactor_savings {
                writeln!(
                    out,
                    "  {} (source {}, artifact {}): {} estimated bytes from {} attributed duplicate bytes; mapping {:?}, clone {:.3}, model {:?}, savings {:?}",
                    estimate.clone_group_fingerprint,
                    estimate.source_build_variant_fingerprint,
                    estimate.artifact_build_variant_fingerprint,
                    estimate.estimated_refactor_savings_bytes.0,
                    estimate.duplicated_bytes,
                    estimate.mapping_confidence,
                    estimate.clone_confidence,
                    estimate.model_confidence,
                    estimate.savings_confidence,
                )?;
                writeln!(out, "    model schema: {}", estimate.model_schema_version)?;
                for assumption in &estimate.assumptions {
                    writeln!(
                        out,
                        "    assumption: {}",
                        refactor_savings_assumption_text(assumption)
                    )?;
                }
            }
        }
        if !correlation.generic_origins.is_empty() {
            writeln!(out, "generic origins (observed symbol bytes):")?;
            for origin in &correlation.generic_origins {
                writeln!(
                    out,
                    "  {} [{}] ({}): {} observed bytes, {} normalized duplicate bytes, {} retained-size sum, {} symbols, {} instantiations across {} translation units",
                    origin.definition,
                    origin.origin_fingerprint,
                    origin.origin_build_variant_fingerprint,
                    origin.observed_symbol_bytes,
                    origin.normalized_instruction_duplicated_bytes,
                    optional_bytes(origin.retained_size_sum),
                    origin.artifact_symbols,
                    origin.instantiations,
                    origin.translation_units,
                )?;
                for specialization in &origin.specializations {
                    let arguments = if specialization.type_arguments.is_empty() {
                        "unparsed arguments".to_owned()
                    } else {
                        specialization.type_arguments.join(", ")
                    };
                    writeln!(
                        out,
                        "    {}: {} observed bytes, {} symbols across {} translation units ({arguments})",
                        specialization.instantiation_key,
                        specialization.observed_symbol_bytes,
                        specialization.artifact_symbols,
                        specialization.translation_units,
                    )?;
                }
            }
        }
        if !correlation.macro_origins.is_empty() {
            writeln!(out, "macro origins (observed symbol bytes):")?;
            for origin in &correlation.macro_origins {
                writeln!(
                    out,
                    "  {} ({}): {} observed bytes across {} symbols ({})",
                    origin.origin_fingerprint,
                    origin.origin_build_variant_fingerprint,
                    origin.observed_symbol_bytes,
                    origin.artifact_symbols,
                    origin.definition_paths.join(", "),
                )?;
            }
        }
    }
    writeln!(out, "data segments: {}", report.data_segments)?;
    writeln!(
        out,
        "duplicates: exact {} groups, {} observed duplicate bytes; normalized {} groups, {} observed duplicate bytes",
        report.duplicates.exact_groups,
        report.duplicates.exact_duplicated_bytes,
        report.duplicates.normalized_groups,
        report.duplicates.normalized_duplicated_bytes,
    )?;
    writeln!(out, "size categories:")?;
    writeln!(out, "  observed_bytes: {}", report.sizes.observed_bytes)?;
    writeln!(out, "  duplicated_bytes: {}", report.sizes.duplicated_bytes)?;
    writeln!(
        out,
        "  retained_bytes: {}",
        optional_bytes(report.sizes.retained_bytes)
    )?;
    writeln!(
        out,
        "  shared_dependency_bytes: {}",
        optional_bytes(report.sizes.shared_dependency_bytes)
    )?;
    writeln!(
        out,
        "  duplicated_data_bytes: {}",
        report.sizes.duplicated_data_bytes
    )?;
    writeln!(
        out,
        "  upper_bound_savings_bytes: {} (upper bound, not guaranteed)",
        optional_bytes(report.sizes.upper_bound_savings_bytes)
    )?;
    writeln!(
        out,
        "  estimated_refactor_savings_bytes: {} (per-clone-group estimates appear under source correlation)",
        optional_estimated_savings(report.sizes.estimated_refactor_savings_bytes)
    )?;
    writeln!(
        out,
        "  verified_savings_bytes: {} (requires a controlled artifact compare calibration)",
        optional_verified_savings(report.sizes.verified_savings_bytes)
    )?;
    writeln!(
        out,
        "  clone_confidence: {:?}",
        report.sizes.clone_confidence
    )?;
    writeln!(
        out,
        "  savings_confidence: {:?}",
        report.sizes.savings_confidence
    )?;
    for assumption in &report.sizes.assumptions {
        writeln!(out, "  assumption: {assumption}")?;
    }
    if let Some(dead_code) = &report.dead_code {
        let verdict = if dead_code.definitive {
            "definitive"
        } else {
            "candidates"
        };
        writeln!(
            out,
            "dead code {verdict}: {} symbols",
            dead_code.symbols.len()
        )?;
        for symbol in &dead_code.symbols {
            writeln!(out, "  {symbol}")?;
        }
        for assumption in &dead_code.assumptions {
            writeln!(out, "  assumption: {assumption}")?;
        }
    } else {
        writeln!(
            out,
            "dead code: unavailable (no resolved exported root set)"
        )?;
    }
    if let Some(retained) = &report.retained_sizes {
        writeln!(out, "retained sizes (overlapping dominator regions):")?;
        for item in retained {
            writeln!(out, "  {} {} bytes", item.symbol, item.retained_bytes)?;
        }
    } else {
        writeln!(
            out,
            "retained sizes: unavailable (incomplete or ambiguous call graph)"
        )?;
    }
    render_groups("exact", &report.duplicate_groups.exact, out)?;
    render_groups("normalized", &report.duplicate_groups.normalized, out)?;
    render_groups("data", &report.duplicate_groups.data, out)?;
    if verbose {
        for import in &report.import_details {
            writeln!(
                out,
                "  import {} {}{}",
                artifact_import_kind_label(import.kind),
                import
                    .module
                    .as_deref()
                    .map_or_else(String::new, |module| format!("{module}::")),
                import.name.as_deref().unwrap_or("<unnamed>"),
            )?;
        }
        for relocation in &report.relocation_details {
            writeln!(
                out,
                "  relocation {} section {} offset {} target {}",
                relocation.kind,
                relocation
                    .section
                    .map_or_else(|| "unknown".to_owned(), |section| section.to_string()),
                relocation.offset,
                relocation.target.as_deref().unwrap_or("<unknown>"),
            )?;
        }
        for segment in &report.data_segment_details {
            writeln!(
                out,
                "  data segment {} section {} offset {} size {}",
                segment.fingerprint,
                segment
                    .section
                    .map_or_else(|| "unknown".to_owned(), |section| section.to_string()),
                segment.offset,
                segment.size,
            )?;
        }
        for symbol in &report.symbols {
            writeln!(
                out,
                "  symbol {} {} offset {} size {}{}",
                symbol.fingerprint,
                symbol.name.as_deref().unwrap_or("<unnamed>"),
                symbol.offset,
                symbol.size,
                if symbol.size_inferred {
                    " (inferred)"
                } else {
                    ""
                },
            )?;
        }
    }
    Ok(())
}

const fn artifact_import_kind_label(kind: codehelion_artifact::ArtifactImportKind) -> &'static str {
    match kind {
        codehelion_artifact::ArtifactImportKind::Function => "function",
        codehelion_artifact::ArtifactImportKind::Table => "table",
        codehelion_artifact::ArtifactImportKind::Memory => "memory",
        codehelion_artifact::ArtifactImportKind::Global => "global",
        codehelion_artifact::ArtifactImportKind::Tag => "tag",
        codehelion_artifact::ArtifactImportKind::Other => "other",
    }
}

fn render_groups(
    kind: &str,
    groups: &[metrics::DuplicateGroup],
    out: &mut impl Write,
) -> Result<()> {
    if groups.is_empty() {
        return Ok(());
    }
    writeln!(out, "{kind} duplicate groups:")?;
    for group in groups {
        writeln!(
            out,
            "  {}: {} observed duplicate bytes, {} members",
            group.fingerprint,
            group.duplicated_bytes,
            group.members.len()
        )?;
        for member in &group.members {
            writeln!(
                out,
                "    {} offset {} size {}",
                member.symbol, member.offset, member.size
            )?;
        }
    }
    Ok(())
}

fn refactor_savings_assumption_text(assumption: &RefactorSavingsAssumption) -> String {
    match assumption {
        RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies } => {
            format!("shared implementation retains {copies} copy/copies")
        }
        RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes } => {
            format!("call overhead is {bytes} bytes per replaced member")
        }
        RefactorSavingsAssumption::InliningOutcomeUnknown => {
            "compiler inlining outcome is unknown".to_owned()
        }
        RefactorSavingsAssumption::LinkerIcfOutcomeUnknown => {
            "linker ICF outcome is unknown".to_owned()
        }
    }
}

fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

fn optional_estimated_savings(value: Option<EstimatedRefactorSavingsBytes>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.0.to_string())
}

fn optional_verified_savings(value: Option<VerifiedSavingsBytes>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.0.to_string())
}

#[allow(clippy::too_many_lines)] // CSV records intentionally remain together to preserve one fixed schema.
pub(super) fn render_csv(report: &ArtifactReport, out: &mut impl Write) -> Result<()> {
    writeln!(
        out,
        "record_type,path,format,kind,fingerprint,name,offset,size,duplicated_bytes,retained_bytes,dead_code_status,observed_bytes,source_run,mappings,mapped_symbols,unmapped_symbols,upper_bound_savings_bytes,estimated_refactor_savings_bytes,verified_savings_bytes,origin_build_variant_fingerprint,instantiations,translation_units,source_build_variant_fingerprint,artifact_build_variant_fingerprint,mapping_confidence,clone_confidence,model_confidence,savings_confidence,model_schema_version,estimate_assumptions_json,section,executable,module"
    )?;
    let correlation = report.correlation.as_ref();
    let mut summary = artifact_csv_row();
    "summary".clone_into(&mut summary[0]);
    summary[1] = csv(&report.path);
    summary[2] = report.format.to_string();
    summary[4].clone_from(&report.fingerprint);
    summary[8] = report.sizes.duplicated_bytes.to_string();
    summary[9] = optional_bytes(report.sizes.retained_bytes);
    summary[11] = report.sizes.observed_bytes.to_string();
    summary[12] = correlation.map_or_else(String::new, |value| value.source_run.to_string());
    summary[13] = correlation.map_or_else(String::new, |value| value.mappings.to_string());
    summary[14] = correlation.map_or_else(String::new, |value| value.mapped_symbols.to_string());
    summary[15] = correlation.map_or_else(String::new, |value| value.unmapped_symbols.to_string());
    summary[16] = optional_bytes(report.sizes.upper_bound_savings_bytes);
    summary[17] = optional_estimated_savings(report.sizes.estimated_refactor_savings_bytes);
    summary[18] = optional_verified_savings(report.sizes.verified_savings_bytes);
    write_artifact_csv_row(out, &summary)?;
    if let Some(variant) = &report.build_variant {
        let mut row = artifact_csv_row();
        "build-variant".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        row[4].clone_from(&variant.fingerprint);
        row[5] = csv(&variant.manifest_path);
        write_artifact_csv_row(out, &row)?;
    }
    for member in &report.archive_members {
        let mut row = artifact_csv_row();
        "archive-member".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        row[3] = member
            .format
            .map_or_else(|| "unknown".to_owned(), |format| format.to_string());
        row[4].clone_from(&member.fingerprint);
        row[5] = csv(&member.name);
        row[6] = member.offset.to_string();
        row[7] = member.size.to_string();
        row[10] = csv(member.parse_error.as_deref().unwrap_or("parsed"));
        write_artifact_csv_row(out, &row)?;
    }
    for section in &report.section_details {
        let mut row = artifact_csv_row();
        "section".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        row[3] = if section.executable {
            "executable".to_owned()
        } else {
            "non-executable".to_owned()
        };
        row[5] = csv(section.name.as_deref().unwrap_or(""));
        row[6] = section.offset.to_string();
        row[7] = section.size.to_string();
        row[31] = section.executable.to_string();
        write_artifact_csv_row(out, &row)?;
    }
    for import in &report.import_details {
        let mut row = artifact_csv_row();
        "import".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        artifact_import_kind_label(import.kind).clone_into(&mut row[3]);
        row[5] = csv(import.name.as_deref().unwrap_or(""));
        row[32] = csv(import.module.as_deref().unwrap_or(""));
        write_artifact_csv_row(out, &row)?;
    }
    for relocation in &report.relocation_details {
        let mut row = artifact_csv_row();
        "relocation".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        row[3] = csv(&relocation.kind);
        row[5] = csv(relocation.target.as_deref().unwrap_or(""));
        row[6] = relocation.offset.to_string();
        row[30] = relocation
            .section
            .map_or_else(String::new, |section| section.to_string());
        write_artifact_csv_row(out, &row)?;
    }
    for segment in &report.data_segment_details {
        let mut row = artifact_csv_row();
        "data-segment".clone_into(&mut row[0]);
        row[1] = csv(&report.path);
        row[2] = report.format.to_string();
        "exact-data".clone_into(&mut row[3]);
        row[4].clone_from(&segment.fingerprint);
        row[6] = segment.offset.to_string();
        row[7] = segment.size.to_string();
        row[30] = segment
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
            let mut row = artifact_csv_row();
            "duplicate-group".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            kind.clone_into(&mut row[3]);
            row[4] = group.fingerprint.to_string();
            row[8] = group.duplicated_bytes.to_string();
            write_artifact_csv_row(out, &row)?;
            for member in &group.members {
                let mut row = artifact_csv_row();
                "duplicate-member".clone_into(&mut row[0]);
                row[1] = csv(&report.path);
                row[2] = report.format.to_string();
                kind.clone_into(&mut row[3]);
                row[4] = member.symbol.to_string();
                row[6] = member.offset.to_string();
                row[7] = member.size.to_string();
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
            let mut row = artifact_csv_row();
            "dead-code".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            row[4] = symbol.to_string();
            status.clone_into(&mut row[10]);
            write_artifact_csv_row(out, &row)?;
        }
    }
    if let Some(retained) = &report.retained_sizes {
        for item in retained {
            let mut row = artifact_csv_row();
            "retained-size".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            row[4] = item.symbol.to_string();
            row[9] = item.retained_bytes.to_string();
            write_artifact_csv_row(out, &row)?;
        }
    }
    if let Some(correlation) = correlation {
        for estimate in &correlation.estimated_refactor_savings {
            let mut row = artifact_csv_row();
            "clone-group-savings".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            "refactor-estimate".clone_into(&mut row[3]);
            row[4].clone_from(&estimate.clone_group_fingerprint);
            row[8] = estimate.duplicated_bytes.to_string();
            row[17] = estimate.estimated_refactor_savings_bytes.0.to_string();
            row[22].clone_from(&estimate.source_build_variant_fingerprint);
            row[23].clone_from(&estimate.artifact_build_variant_fingerprint);
            row[24] = format!("{:?}", estimate.mapping_confidence);
            row[25] = format!("{:.3}", estimate.clone_confidence);
            row[26] = format!("{:?}", estimate.model_confidence);
            row[27] = format!("{:?}", estimate.savings_confidence);
            estimate.model_schema_version.clone_into(&mut row[28]);
            row[29] = csv(&serde_json::to_string(&estimate.assumptions)
                .context("serializing CSV refactoring-estimate assumptions")?);
            write_artifact_csv_row(out, &row)?;
        }
        for origin in &correlation.generic_origins {
            let mut row = artifact_csv_row();
            "generic-origin".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            "generic-origin".clone_into(&mut row[3]);
            row[4].clone_from(&origin.origin_fingerprint);
            row[5].clone_from(&origin.definition);
            row[7] = origin.observed_symbol_bytes.to_string();
            row[8] = origin.normalized_instruction_duplicated_bytes.to_string();
            row[19].clone_from(&origin.origin_build_variant_fingerprint);
            row[20] = origin.instantiations.to_string();
            row[21] = origin.translation_units.to_string();
            write_artifact_csv_row(out, &row)?;
            for specialization in &origin.specializations {
                let mut row = artifact_csv_row();
                "generic-specialization".clone_into(&mut row[0]);
                row[1] = csv(&report.path);
                row[2] = report.format.to_string();
                "generic-origin".clone_into(&mut row[3]);
                row[4].clone_from(&origin.origin_fingerprint);
                row[5] = csv(&specialization.instantiation_key);
                row[7] = specialization.observed_symbol_bytes.to_string();
                row[19].clone_from(&origin.origin_build_variant_fingerprint);
                "1".clone_into(&mut row[20]);
                row[21] = specialization.translation_units.to_string();
                write_artifact_csv_row(out, &row)?;
            }
        }
        for origin in &correlation.macro_origins {
            let mut row = artifact_csv_row();
            "macro-origin".clone_into(&mut row[0]);
            row[1] = csv(&report.path);
            row[2] = report.format.to_string();
            "macro-origin".clone_into(&mut row[3]);
            row[4].clone_from(&origin.origin_fingerprint);
            row[5] = csv(&origin.definition_paths.join(";"));
            row[7] = origin.observed_symbol_bytes.to_string();
            row[19].clone_from(&origin.origin_build_variant_fingerprint);
            row[20] = origin.artifact_symbols.to_string();
            row[21] = origin.definition_paths.len().to_string();
            write_artifact_csv_row(out, &row)?;
        }
    }
    Ok(())
}

fn artifact_csv_row() -> Vec<String> {
    vec![String::new(); ARTIFACT_CSV_COLUMNS]
}

fn write_artifact_csv_row(out: &mut impl Write, row: &[String]) -> Result<()> {
    debug_assert_eq!(row.len(), ARTIFACT_CSV_COLUMNS);
    writeln!(out, "{}", row.join(","))?;
    Ok(())
}

pub(super) fn render_compare_csv(
    report: &ArtifactComparisonReport,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(
        out,
        "record_type,before_path,after_path,before_format,after_format,before_fingerprint,after_fingerprint,observed_size_reduction_bytes,duplicated_code_delta_bytes,duplicated_data_delta_bytes,estimated_refactor_savings_bytes,verified_savings_bytes,source_run,clone_group_fingerprint,change_kind,name,fingerprint,symbol_size_delta_bytes,duplicated_bytes_delta,members_delta,warning,absolute_error_bytes,relative_error"
    )?;
    write_compare_csv_row(out, &compare_csv_row(report, "summary"))?;
    for delta in &report.symbol_deltas {
        let mut row = compare_csv_row(report, "symbol-delta");
        delta.kind.clone_into(&mut row[14]);
        row[15] = csv(delta.name.as_deref().unwrap_or(""));
        row[16].clone_from(&delta.fingerprint);
        row[17] = delta.size_delta_bytes.to_string();
        write_compare_csv_row(out, &row)?;
    }
    for delta in &report.duplicate_group_deltas {
        let mut row = compare_csv_row(report, "duplicate-group-delta");
        delta.kind.clone_into(&mut row[14]);
        row[16].clone_from(&delta.fingerprint);
        row[18] = delta.duplicated_bytes_delta.to_string();
        row[19] = delta.members_delta.to_string();
        write_compare_csv_row(out, &row)?;
    }
    if let Some(warning) = &report.build_variant_warning {
        let mut row = compare_csv_row(report, "build-variant-warning");
        row[20] = csv(warning);
        write_compare_csv_row(out, &row)?;
    }
    if let Some(calibration) = &report.calibration {
        let mut row = compare_csv_row(report, "calibration");
        row[10] = calibration.estimated_refactor_savings_bytes.0.to_string();
        row[11] = calibration.verified_savings_bytes.0.to_string();
        row[12] = calibration.source_run.to_string();
        row[13].clone_from(&calibration.clone_group_fingerprint);
        row[21] = calibration.absolute_error_bytes.to_string();
        row[22] = optional_f64(calibration.relative_error);
        write_compare_csv_row(out, &row)?;
    }
    Ok(())
}

const COMPARE_CSV_COLUMNS: usize = 23;

fn compare_csv_row(report: &ArtifactComparisonReport, record_type: &str) -> Vec<String> {
    let mut row = vec![String::new(); COMPARE_CSV_COLUMNS];
    record_type.clone_into(&mut row[0]);
    row[1] = csv(&report.before.path);
    row[2] = csv(&report.after.path);
    row[3] = report.before.format.to_string();
    row[4] = report.after.format.to_string();
    row[5].clone_from(&report.before.fingerprint);
    row[6].clone_from(&report.after.fingerprint);
    row[7] = report.observed_size_reduction_bytes.0.to_string();
    row[8] = report.duplicated_code_delta_bytes.to_string();
    row[9] = report.duplicated_data_delta_bytes.to_string();
    row
}

fn write_compare_csv_row(out: &mut impl Write, row: &[String]) -> Result<()> {
    debug_assert_eq!(row.len(), COMPARE_CSV_COLUMNS);
    writeln!(out, "{}", row.join(",")).map_err(Into::into)
}

pub(super) fn render_compare_text(
    report: &ArtifactComparisonReport,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(
        out,
        "before: {} ({})",
        report.before.path, report.before.format
    )?;
    writeln!(
        out,
        "after: {} ({})",
        report.after.path, report.after.format
    )?;
    if let Some(variant) = &report.before.build_variant {
        writeln!(
            out,
            "before build variant: {} ({})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(variant) = &report.after.build_variant {
        writeln!(
            out,
            "after build variant: {} ({})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(warning) = &report.build_variant_warning {
        writeln!(out, "build variant warning: {warning}")?;
    }
    writeln!(
        out,
        "observed_size_reduction_bytes: {:+}",
        report.observed_size_reduction_bytes.0
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
    }
    writeln!(
        out,
        "duplicated_code_delta_bytes: {:+}",
        report.duplicated_code_delta_bytes
    )?;
    writeln!(
        out,
        "duplicated_data_delta_bytes: {:+}",
        report.duplicated_data_delta_bytes
    )?;
    writeln!(
        out,
        "symbols: {} added, {} removed, {} named modified",
        report.symbol_changes.added,
        report.symbol_changes.removed,
        report.symbol_changes.modified_named_symbols,
    )?;
    for delta in &report.symbol_deltas {
        writeln!(
            out,
            "  {} {} {} {:+} bytes",
            delta.kind,
            delta.name.as_deref().unwrap_or("<unnamed>"),
            delta.fingerprint,
            delta.size_delta_bytes
        )?;
    }
    for delta in &report.duplicate_group_deltas {
        writeln!(
            out,
            "  duplicate {} {} {:+} bytes, {:+} members",
            delta.kind, delta.fingerprint, delta.duplicated_bytes_delta, delta.members_delta,
        )?;
    }
    for assumption in &report.assumptions {
        writeln!(out, "assumption: {assumption}")?;
    }
    Ok(())
}
