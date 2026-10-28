//! Human-readable rendering of one artifact report.

use std::borrow::Cow;
use std::collections::HashMap;

use codehelion_artifact::metrics::ReportedSize;
use codehelion_artifact::ownership::Ownership;

use super::{
    artifact_import_kind_label, attribution_basis_label, counted, display_name, listed_names, noun,
    optional_bytes, refactor_savings_assumption_text, render_fact_lines, render_omitted,
    stated_bytes, symbol_names,
};
use crate::artifact::model::{
    ARTIFACT_FACTS, ArtifactReport, AssumptionScope, DuplicateGroupReport, NameStemReport,
    OwnershipReport, ReportAssumption, SourceMapResolutionStatus, ToolchainHoldingsReport,
    dead_code_unavailability, family_label, ownership_label, report_assumptions,
    retained_size_unavailability,
};
use crate::artifact::{Result, Write};

#[allow(clippy::too_many_lines)] // The report order is its public text contract.
pub(in crate::artifact) fn render_text(
    report: &ArtifactReport,
    verbose: bool,
    out: &mut impl Write,
) -> Result<()> {
    render_fact_lines(ARTIFACT_FACTS, report, out)?;
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
            "untrusted containment: input {}, worker timeout {}s, worker memory {}, \
             debug-derived structures {}",
            counted(containment.max_input_bytes, "byte", "bytes"),
            containment.worker_timeout_seconds,
            counted(containment.worker_memory_limit_bytes, "byte", "bytes"),
            containment.max_debug_derived_items,
        )?;
    }
    writeln!(out, "observed bytes: {}", report.observed_bytes)?;
    writeln!(out, "code section bytes: {}", report.code_section_bytes)?;
    writeln!(out, "data segment bytes: {}", report.data_segment_bytes)?;
    for size in &report.compressed_sizes {
        writeln!(
            out,
            "compressed bytes ({}, {}, {}): {}",
            size.algorithm, size.parameters, size.encoder, size.bytes
        )?;
    }
    if !report.compressed_sizes.is_empty() {
        writeln!(
            out,
            "  note: the compressed size covers the whole artifact; it is not divided among symbols, and an external compressor at the same level can differ by a fraction of a percent"
        )?;
    }
    if !report.section_details.is_empty() {
        writeln!(out, "section sizes:")?;
        for section in &report.section_details {
            writeln!(
                out,
                "  {}: offset {}, {}{}",
                section.name.as_deref().unwrap_or("<unnamed>"),
                section.offset,
                counted(section.size, "byte", "bytes"),
                if section.executable {
                    " (executable)"
                } else {
                    ""
                }
            )?;
        }
    }
    // Every rendering takes its qualifying statements from one description of
    // the report, so a reader of any one format sees the same set.
    let assumptions = report_assumptions(report);
    writeln!(out, "symbols: {}", report.symbols.len())?;
    render_assumptions(&assumptions, AssumptionScope::Symbols, out)?;
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
                    "  {}: resolved to {local_path} ({})",
                    map.uri,
                    counted(sources.len(), "source", "sources")
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
            "source correlation: scan {}: {}, {}/{} ({:.1}%), {} / {} ({:.1}%), {} ({})",
            correlation.source_run,
            counted(correlation.mappings, "mapping", "mappings"),
            correlation.mapped_symbols,
            counted(
                correlation.artifact_symbols,
                "mapped symbol",
                "mapped symbols"
            ),
            correlation.mapping_coverage * 100.0,
            correlation.mapped_symbol_bytes,
            counted(
                report.symbols.iter().map(|symbol| symbol.size).sum::<u64>(),
                "mapped symbol byte",
                "mapped symbol bytes"
            ),
            correlation.mapped_symbol_bytes_ratio * 100.0,
            counted(
                correlation.unmapped_symbols,
                "unmapped symbol",
                "unmapped symbols"
            ),
            counted(correlation.unmapped_symbol_bytes, "byte", "bytes"),
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
                    "  {} ({}): {} / {} attributed, observed duplicated bytes: {}, line-proportional duplicated bytes: {} (estimated), in {} totalling {}",
                    attribution.clone_group_fingerprint,
                    attribution.source_build_variant_fingerprint,
                    attribution.attributed_noncanonical_members,
                    counted(
                        attribution.members.saturating_sub(1),
                        "noncanonical member",
                        "noncanonical members"
                    ),
                    optional_bytes(attribution.duplicated_bytes),
                    optional_bytes(attribution.estimated_duplicated_bytes),
                    counted(attribution.containing_symbols, "symbol", "symbols"),
                    attribution.containing_symbol_bytes.map_or_else(
                        || "unavailable observed bytes".to_owned(),
                        |bytes| counted(bytes, "observed byte", "observed bytes")
                    ),
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
                    "  {} ({}){}: {}, {}, mapping {:?}",
                    unit.source_fingerprint,
                    unit.source_build_variant_fingerprint,
                    unit.name
                        .as_deref()
                        .map_or_else(String::new, |name| format!(" {name}")),
                    counted(unit.emitted_bodies, "body", "bodies"),
                    counted(
                        unit.observed_symbol_bytes,
                        "observed byte",
                        "observed bytes"
                    ),
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
                    "  {} (source {}, artifact {}): {} from {} {} {}; mapping {:?}, clone {:.3}, model {:?}, savings {:?}",
                    estimate.clone_group_fingerprint,
                    estimate.source_build_variant_fingerprint,
                    estimate.artifact_build_variant_fingerprint,
                    counted(
                        estimate.estimated_refactor_savings_bytes.0,
                        "estimated byte",
                        "estimated bytes"
                    ),
                    estimate.duplicated_bytes,
                    attribution_basis_label(estimate.duplicated_bytes_basis),
                    noun(
                        estimate.duplicated_bytes,
                        "duplicate byte",
                        "duplicate bytes"
                    ),
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
                    "  {} [{}] ({}): {}, {}, {} retained-size sum, {}, {} across {}",
                    origin.definition,
                    origin.origin_fingerprint,
                    origin.origin_build_variant_fingerprint,
                    counted(
                        origin.observed_symbol_bytes,
                        "observed byte",
                        "observed bytes"
                    ),
                    counted(
                        origin.normalized_instruction_duplicated_bytes,
                        "normalized duplicate byte",
                        "normalized duplicate bytes"
                    ),
                    optional_bytes(origin.retained_size_sum),
                    counted(origin.artifact_symbols, "symbol", "symbols"),
                    counted(origin.instantiations, "instantiation", "instantiations"),
                    counted(
                        origin.translation_units,
                        "translation unit",
                        "translation units"
                    ),
                )?;
                for specialization in &origin.specializations {
                    let arguments = if specialization.type_arguments.is_empty() {
                        "unparsed arguments".to_owned()
                    } else {
                        specialization.type_arguments.join(", ")
                    };
                    writeln!(
                        out,
                        "    {}: {}, {} across {} ({arguments})",
                        specialization.instantiation_key,
                        counted(
                            specialization.observed_symbol_bytes,
                            "observed byte",
                            "observed bytes"
                        ),
                        counted(specialization.artifact_symbols, "symbol", "symbols"),
                        counted(
                            specialization.translation_units,
                            "translation unit",
                            "translation units"
                        ),
                    )?;
                }
            }
        }
        if !correlation.macro_origins.is_empty() {
            writeln!(out, "macro origins (observed symbol bytes):")?;
            for origin in &correlation.macro_origins {
                writeln!(
                    out,
                    "  {} ({}): {} across {} ({})",
                    origin.origin_fingerprint,
                    origin.origin_build_variant_fingerprint,
                    counted(
                        origin.observed_symbol_bytes,
                        "observed byte",
                        "observed bytes"
                    ),
                    counted(origin.artifact_symbols, "symbol", "symbols"),
                    origin.definition_paths.join(", "),
                )?;
            }
        }
    }
    if report.capabilities.normalized_duplicates {
        writeln!(
            out,
            "duplicates: exact {}, {}; normalized {}, {}",
            counted(report.duplicates.exact_groups, "group", "groups"),
            counted(
                report.duplicates.exact_duplicated_bytes,
                "observed duplicate byte",
                "observed duplicate bytes"
            ),
            counted(report.duplicates.normalized_groups, "group", "groups"),
            counted(
                report.duplicates.normalized_duplicated_bytes,
                "observed duplicate byte",
                "observed duplicate bytes"
            ),
        )?;
    } else {
        writeln!(
            out,
            "duplicates: exact {}, {}; normalized unavailable (no normalizer for this architecture)",
            counted(report.duplicates.exact_groups, "group", "groups"),
            counted(
                report.duplicates.exact_duplicated_bytes,
                "observed duplicate byte",
                "observed duplicate bytes"
            ),
        )?;
    }
    let names = symbol_names(report);
    let label = |fingerprint: &str| listed_names(&names, fingerprint, verbose);
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
    render_assumptions(&assumptions, AssumptionScope::Sizes, out)?;
    if let Some(dead_code) = &report.dead_code {
        let verdict = if dead_code.definitive {
            "definitive"
        } else {
            "candidates"
        };
        writeln!(
            out,
            "dead code {verdict}: {}",
            counted(dead_code.symbols.len(), "symbol", "symbols")
        )?;
        for symbol in &dead_code.symbols {
            writeln!(out, "  {} {symbol}", label(symbol))?;
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
            writeln!(
                out,
                "  {} {}: {}",
                label(&item.symbol),
                item.symbol,
                counted(item.retained_bytes, "byte", "bytes")
            )?;
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
    render_ownership(&report.ownership, &assumptions, out)?;
    render_name_stems(&report.name_stems, verbose, &assumptions, out)?;
    match &report.toolchain_holdings {
        Some(holdings) => render_holdings(holdings, verbose, &assumptions, out)?,
        // The retained-size line above already named the conditions.
        None => writeln!(
            out,
            "toolchain holders: unavailable (same conditions as retained sizes)"
        )?,
    }
    render_groups(
        "exact",
        &report.duplicate_groups.exact,
        Some(&names),
        verbose,
        out,
    )?;
    render_groups(
        "normalized",
        &report.duplicate_groups.normalized,
        Some(&names),
        verbose,
        out,
    )?;
    render_groups("data", &report.duplicate_groups.data, None, verbose, out)?;
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

/// Owners listed in text; JSON carries every one.
const LISTED_OWNERS: usize = 10;
/// Holders listed in text.
const LISTED_HOLDERS: usize = 10;
/// Heads listed under each holder.
const LISTED_HEADS: usize = 3;
/// Shared toolchain entries listed in text.
const LISTED_SHARED: usize = 5;
/// Callers listed under each shared entry.
const LISTED_CALLERS: usize = 3;

/// The class split on one line, then the largest owners and what lies outside
/// every symbol.
fn render_ownership(
    ownership: &OwnershipReport,
    assumptions: &[ReportAssumption<'_>],
    out: &mut impl Write,
) -> Result<()> {
    let classes: Vec<String> = ownership
        .classes
        .iter()
        .map(|class| {
            format!(
                "{} {} ({})",
                ownership_label(class.ownership),
                counted(class.size_bytes, "byte", "bytes"),
                counted(class.symbols, "symbol", "symbols")
            )
        })
        .collect();
    writeln!(out, "ownership: {}", classes.join(", "))?;
    if !ownership.declared_own.is_empty() {
        writeln!(out, "  declared own: {}", ownership.declared_own.join(", "))?;
    }
    // The unnamed class has one key, which the class line already states.
    let owners: Vec<_> = ownership
        .owners
        .iter()
        .filter(|owner| owner.ownership != Ownership::Unnamed)
        .collect();
    for owner in owners.iter().take(LISTED_OWNERS) {
        let family = owner
            .family
            .map_or_else(String::new, |family| format!(", {}", family_label(family)));
        writeln!(
            out,
            "  {} ({}{family}): {}, {}",
            owner.key,
            ownership_label(owner.ownership),
            counted(owner.size_bytes, "byte", "bytes"),
            counted(owner.symbols, "symbol", "symbols")
        )?;
    }
    render_omitted(owners.len(), LISTED_OWNERS, "owner", "owners", "  ", out)?;
    writeln!(
        out,
        "  outside symbols: {}",
        counted(ownership.outside_symbols_bytes, "byte", "bytes")
    )?;
    render_assumptions(assumptions, AssumptionScope::Ownership, out)
}

/// The stems emitted as several bodies, largest first, with the instances of
/// each under `--verbose`. Nothing is written while there are none.
fn render_name_stems(
    stems: &[NameStemReport],
    verbose: bool,
    assumptions: &[ReportAssumption<'_>],
    out: &mut impl Write,
) -> Result<()> {
    if stems.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "name stems emitted as several bodies (observed, not savings):"
    )?;
    for stem in stems.iter().take(LISTED_OWNERS) {
        writeln!(
            out,
            "  {} ({}): {} in {}, {}",
            stem.stem,
            ownership_label(stem.ownership),
            counted(stem.bodies, "body", "bodies"),
            counted(stem.instances, "instance", "instances"),
            counted(stem.size_bytes, "byte", "bytes")
        )?;
        if verbose {
            for instance in &stem.instance_details {
                writeln!(
                    out,
                    "    {}: {}, {}",
                    instance.instance,
                    counted(instance.bodies, "body", "bodies"),
                    counted(instance.size_bytes, "byte", "bytes")
                )?;
            }
        }
    }
    render_omitted(stems.len(), LISTED_OWNERS, "stem", "stems", "  ", out)?;
    writeln!(
        out,
        "  note: a stem groups bodies whose names differ only in template arguments, closure numbering or parameter lists; one source template written once can account for all of them, so the bytes are what the artifact spends, not what consolidating source would remove"
    )?;
    render_assumptions(assumptions, AssumptionScope::NameStems, out)
}

/// The largest holders with their heads, then the shared toolchain code.
fn render_holdings(
    holdings: &ToolchainHoldingsReport,
    verbose: bool,
    assumptions: &[ReportAssumption<'_>],
    out: &mut impl Write,
) -> Result<()> {
    writeln!(
        out,
        "toolchain holders (held bytes are part of the holder's retained size):"
    )?;
    for holding in holdings.holdings.iter().take(LISTED_HOLDERS) {
        writeln!(
            out,
            "  {} ({}) {}: {} in {}, {} in {} absorbed",
            display_name(holding.holder_name.as_deref(), verbose),
            ownership_label(holding.holder_ownership),
            holding.holder,
            counted(holding.held_bytes, "byte", "bytes"),
            counted(holding.held_symbols, "symbol", "symbols"),
            counted(holding.absorbed_bytes, "byte", "bytes"),
            counted(holding.absorbed_symbols, "symbol", "symbols"),
        )?;
        for head in holding.heads.iter().take(LISTED_HEADS) {
            writeln!(
                out,
                "    head {} {}: {}",
                display_name(head.name.as_deref(), verbose),
                head.symbol,
                counted(head.held_bytes, "byte", "bytes")
            )?;
        }
        render_omitted(
            holding.heads.len(),
            LISTED_HEADS,
            "head",
            "heads",
            "    ",
            out,
        )?;
    }
    render_omitted(
        holdings.holdings.len(),
        LISTED_HOLDERS,
        "holder",
        "holders",
        "  ",
        out,
    )?;
    writeln!(
        out,
        "  shared: {} in {}, {} in {} absorbed",
        counted(holdings.shared_bytes, "byte", "bytes"),
        counted(holdings.shared_symbols, "symbol", "symbols"),
        counted(holdings.shared_absorbed_bytes, "byte", "bytes"),
        counted(holdings.shared_absorbed_symbols, "symbol", "symbols"),
    )?;
    for shared in holdings.shared.iter().take(LISTED_SHARED) {
        let callers: Vec<String> = shared
            .callers
            .iter()
            .take(LISTED_CALLERS)
            .map(|caller| {
                format!(
                    "{} ({})",
                    caller.name.as_deref().map_or_else(
                        || Cow::Borrowed(caller.symbol.as_str()),
                        |name| display_name(Some(name), verbose)
                    ),
                    ownership_label(caller.ownership)
                )
            })
            .collect();
        let more = shared.callers.len().saturating_sub(LISTED_CALLERS);
        let more = if more > 0 {
            format!(", {more} more")
        } else {
            String::new()
        };
        writeln!(
            out,
            "    {} {}: {}{}, called by {}{more}",
            display_name(shared.name.as_deref(), verbose),
            shared.symbol,
            counted(shared.held_bytes, "byte", "bytes"),
            if shared.root { " (root)" } else { "" },
            if callers.is_empty() {
                "nothing".to_owned()
            } else {
                callers.join(", ")
            },
        )?;
    }
    render_omitted(
        holdings.shared.len(),
        LISTED_SHARED,
        "shared entry",
        "shared entries",
        "    ",
        out,
    )?;
    render_assumptions(assumptions, AssumptionScope::ToolchainHoldings, out)
}

/// One duplicate group list. Symbol groups name their members from `names`;
/// data groups pass `None`, because a data member is a segment, not a symbol.
fn render_groups(
    kind: &str,
    groups: &[DuplicateGroupReport],
    names: Option<&HashMap<&str, Vec<&str>>>,
    verbose: bool,
    out: &mut impl Write,
) -> Result<()> {
    if groups.is_empty() {
        return Ok(());
    }
    writeln!(out, "{kind} duplicate groups:")?;
    for group in groups {
        writeln!(
            out,
            "  {}: {}, {}",
            group.fingerprint,
            counted(
                group.duplicated_bytes,
                "observed duplicate byte",
                "observed duplicate bytes"
            ),
            counted(group.members.len(), "member", "members")
        )?;
        for member in &group.members {
            let name = names.map(|names| listed_names(names, &member.symbol, verbose));
            match name {
                Some(name) => writeln!(
                    out,
                    "    {name} {} offset {} size {}",
                    member.symbol, member.offset, member.size
                )?,
                None => writeln!(
                    out,
                    "    {} offset {} size {}",
                    member.symbol, member.offset, member.size
                )?,
            }
        }
    }
    Ok(())
}
