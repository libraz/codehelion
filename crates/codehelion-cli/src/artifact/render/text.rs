//! Human-readable rendering of one artifact report.

use codehelion_artifact::metrics::ReportedSize;

use super::{
    artifact_import_kind_label, attribution_basis_label, optional_bytes,
    refactor_savings_assumption_text, stated_bytes,
};
use crate::artifact::model::{
    ArtifactReport, AssumptionScope, ReportAssumption, SourceMapResolutionStatus,
    dead_code_unavailability, report_assumptions, retained_size_unavailability,
};
use crate::artifact::{Result, Write, metrics};

#[allow(clippy::too_many_lines)] // The report order is its public text contract.
pub(in crate::artifact) fn render_text(
    report: &ArtifactReport,
    verbose: bool,
    out: &mut impl Write,
) -> Result<()> {
    writeln!(out, "artifact: {}", report.path)?;
    writeln!(out, "format: {}", report.format)?;
    if let Some(architecture) = &report.architecture {
        writeln!(out, "architecture: {architecture}")?;
    }
    if !report.skipped_architectures.is_empty() {
        writeln!(
            out,
            "skipped architectures: {}",
            report.skipped_architectures.join(", ")
        )?;
    }
    writeln!(out, "fingerprint: {}", report.fingerprint)?;
    if let Some(variant) = &report.build_variant {
        writeln!(
            out,
            "build variant: {} (digest {})",
            variant.manifest_path, variant.fingerprint
        )?;
    }
    if let Some(containment) = &report.containment {
        writeln!(
            out,
            "untrusted containment: input {} bytes, worker timeout {}s, worker memory {} bytes, \
             debug-derived structures {}",
            containment.max_input_bytes,
            containment.worker_timeout_seconds,
            containment.worker_memory_limit_bytes,
            containment.max_debug_derived_items,
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
        // Each declared reference states its own outcome, as it does in the
        // JSON and CSV renderings of the same report.
        for map in &report.source_maps {
            match &map.status {
                SourceMapResolutionStatus::Resolved {
                    local_path,
                    sources,
                    ..
                } => writeln!(
                    out,
                    "  {}: resolved to {local_path} ({} sources)",
                    map.uri,
                    sources.len()
                )?,
                SourceMapResolutionStatus::Unavailable { reason } => {
                    writeln!(out, "  {}: unavailable ({reason})", map.uri)?;
                }
            }
        }
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
                    "  {} ({}): {} / {} noncanonical members attributed, observed duplicated bytes: {}, line-proportional duplicated bytes: {} (estimated), in {} symbol(s) totalling {} observed bytes",
                    attribution.clone_group_fingerprint,
                    attribution.source_build_variant_fingerprint,
                    attribution.attributed_noncanonical_members,
                    attribution.members.saturating_sub(1),
                    optional_bytes(attribution.duplicated_bytes),
                    optional_bytes(attribution.estimated_duplicated_bytes),
                    attribution.containing_symbols,
                    optional_bytes(attribution.containing_symbol_bytes),
                )?;
            }
            writeln!(
                out,
                "  note: the containing symbols hold the members and are usually larger than them, so their size bounds what the group occupies rather than measuring it",
            )?;
        }
        if !correlation.multiply_emitted_units.is_empty() {
            writeln!(
                out,
                "source units emitted as several bodies (observed, not savings):"
            )?;
            for unit in &correlation.multiply_emitted_units {
                writeln!(
                    out,
                    "  {} ({}){}: {} bodies, {} observed bytes, mapping {:?}",
                    unit.source_fingerprint,
                    unit.source_build_variant_fingerprint,
                    unit.name
                        .as_deref()
                        .map_or_else(String::new, |name| format!(" {name}")),
                    unit.emitted_bodies,
                    unit.observed_symbol_bytes,
                    unit.mapping_confidence,
                )?;
            }
            writeln!(
                out,
                "  note: one source copy emitted as several bodies is not duplicated source, so consolidating the copy removes none of them; reducing the count means emitting fewer bodies",
            )?;
        }
        if !correlation.estimated_refactor_savings.is_empty() {
            writeln!(out, "clone group refactoring estimates (not guaranteed):")?;
            for estimate in &correlation.estimated_refactor_savings {
                writeln!(
                    out,
                    "  {} (source {}, artifact {}): {} estimated bytes from {} {} duplicate bytes; mapping {:?}, clone {:.3}, model {:?}, savings {:?}",
                    estimate.clone_group_fingerprint,
                    estimate.source_build_variant_fingerprint,
                    estimate.artifact_build_variant_fingerprint,
                    estimate.estimated_refactor_savings_bytes.0,
                    estimate.duplicated_bytes,
                    attribution_basis_label(estimate.duplicated_bytes_basis),
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
    if report.capabilities.normalized_duplicates {
        writeln!(
            out,
            "duplicates: exact {} groups, {} observed duplicate bytes; normalized {} groups, {} observed duplicate bytes",
            report.duplicates.exact_groups,
            report.duplicates.exact_duplicated_bytes,
            report.duplicates.normalized_groups,
            report.duplicates.normalized_duplicated_bytes,
        )?;
    } else {
        writeln!(
            out,
            "duplicates: exact {} groups, {} observed duplicate bytes; normalized unavailable (no normalizer for this architecture)",
            report.duplicates.exact_groups, report.duplicates.exact_duplicated_bytes,
        )?;
    }
    writeln!(out, "size categories:")?;
    // One line per category the classification states, in its order, each
    // naming the evidence behind it. A reader who came for size reads this
    // block and nothing else, so a category reachable only in another format
    // would be one they never learn exists.
    for (category, bytes) in report.sizes.stated() {
        let qualification = category
            .qualification()
            .map_or_else(String::new, |note| format!(" ({note})"));
        writeln!(
            out,
            "  {}: {}{qualification}",
            category.key(),
            stated_bytes(bytes)
        )?;
    }
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
    // Every rendering takes its qualifying statements from one description of
    // the report, so a reader of any one format sees the same set.
    let assumptions = report_assumptions(report);
    render_assumptions(&assumptions, AssumptionScope::Sizes, out)?;
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
        render_assumptions(&assumptions, AssumptionScope::DeadCode, out)?;
    } else {
        writeln!(
            out,
            "dead code: unavailable ({})",
            dead_code_unavailability(report)
        )?;
    }
    if let Some(retained) = &report.retained_sizes {
        writeln!(out, "retained sizes (overlapping dominator regions):")?;
        for item in retained {
            writeln!(out, "  {} {} bytes", item.symbol, item.retained_bytes)?;
        }
    } else {
        // The conditions come from the walk that withdrew the values, so this
        // line never names a cause that did not hold for this artifact.
        let unavailable = retained_size_unavailability(report);
        if unavailable.is_empty() {
            writeln!(out, "retained sizes: unavailable")?;
        } else {
            writeln!(
                out,
                "retained sizes: unavailable ({})",
                unavailable.join("; ")
            )?;
        }
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

/// Print the statements of one scope, indented under the block they qualify.
fn render_assumptions(
    assumptions: &[ReportAssumption<'_>],
    scope: AssumptionScope,
    out: &mut impl Write,
) -> Result<()> {
    for assumption in assumptions
        .iter()
        .filter(|assumption| assumption.scope == scope)
    {
        writeln!(out, "  assumption: {}", assumption.text)?;
    }
    Ok(())
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
