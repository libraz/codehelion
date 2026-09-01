//! Human-readable and CSV artifact report rendering.

use super::correlation::{self, AttributionBasis, RefactorSavingsAssumption};
use super::model::{
    ARTIFACT_CSV_HEADER, ArtifactComparisonReport, ArtifactReport, AssumptionScope,
    COMPARE_CSV_HEADER, ReportAssumption, SourceMapResolutionStatus, column, compare_column,
    comparison_assumptions, dead_code_unavailability, pairs_both_artifacts, report_assumptions,
    retained_size_unavailability,
};
use super::{Context, Result, Write, csv, metrics, optional_f64};
use codehelion_artifact::metrics::ReportedSize;

#[allow(clippy::too_many_lines)] // The report order is its public text contract.
pub(super) fn render_text(
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
            "untrusted containment: input {} bytes, worker timeout {}s, worker memory {} bytes",
            containment.max_input_bytes,
            containment.worker_timeout_seconds,
            containment.worker_memory_limit_bytes,
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

/// Name the evidence behind one attributed byte count wherever it is printed.
const fn attribution_basis_label(basis: AttributionBasis) -> &'static str {
    match basis {
        AttributionBasis::Observed => "observed attributed",
        AttributionBasis::LineProportional => "line-proportional estimated",
    }
}

/// The CSV spelling of the same evidence class.
const fn attribution_basis_field(basis: AttributionBasis) -> &'static str {
    match basis {
        AttributionBasis::Observed => "observed",
        AttributionBasis::LineProportional => "line_proportional_estimate",
    }
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
        RefactorSavingsAssumption::AttributionIsLineProportional => {
            "at least one member's bytes were divided across its symbol's source lines rather than observed".to_owned()
        }
    }
}

pub(super) fn optional_bytes(value: Option<u64>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

/// One stated size category's value, or the word for evidence that is absent.
///
/// The absence is spelled the same way whatever the category, because "the
/// evidence for this is not there" is one fact and a reader comparing two
/// lines should not have to tell two spellings of it apart.
pub(super) fn stated_bytes(value: Option<i128>) -> String {
    value.map_or_else(|| "unavailable".to_owned(), |value| value.to_string())
}

/// The column one clone-group byte count is written to.
///
/// Taken apart exhaustively for the same reason the artifact-wide mapping is:
/// a count added to the attribution stops this compiling until it is given a
/// column of its own, rather than sharing one with a count of another kind.
pub(super) const fn attribution_column(category: correlation::GroupSizeCategory) -> usize {
    match category {
        correlation::GroupSizeCategory::Duplicated => column::DUPLICATED_BYTES,
        correlation::GroupSizeCategory::EstimatedDuplicated => column::ESTIMATED_DUPLICATED_BYTES,
        correlation::GroupSizeCategory::ContainingSymbols => column::CONTAINING_SYMBOL_BYTES,
    }
}

/// The summary column one size category is written to.
///
/// Taken apart exhaustively: a category added to the classification stops this
/// compiling until it is given a column, which is what stops a number reaching
/// the text and JSON views while the record a consumer parses leaves it out.
/// Columns are only ever appended, so a new category takes a new one.
const fn summary_column(category: metrics::SizeCategory) -> usize {
    match category {
        metrics::SizeCategory::Observed => column::OBSERVED_BYTES,
        metrics::SizeCategory::Duplicated => column::DUPLICATED_BYTES,
        metrics::SizeCategory::DuplicatedNormalized => column::DUPLICATED_BYTES_NORMALIZED,
        metrics::SizeCategory::Retained => column::RETAINED_BYTES,
        metrics::SizeCategory::SharedDependency => column::SHARED_DEPENDENCY_BYTES,
        metrics::SizeCategory::DuplicatedData => column::DUPLICATED_DATA_BYTES,
        metrics::SizeCategory::UpperBoundSavings => column::UPPER_BOUND_SAVINGS_BYTES,
        metrics::SizeCategory::EstimatedRefactorSavings => column::ESTIMATED_REFACTOR_SAVINGS_BYTES,
        metrics::SizeCategory::VerifiedSavings => column::VERIFIED_SAVINGS_BYTES,
    }
}

#[allow(clippy::too_many_lines)] // CSV records intentionally remain together to preserve one fixed schema.
pub(super) fn render_csv(report: &ArtifactReport, out: &mut impl Write) -> Result<()> {
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

pub(super) fn render_compare_csv(
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
pub(super) fn render_compare_text(
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
