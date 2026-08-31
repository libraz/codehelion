//! Scan report serialization and partitioned output rendering.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the implementation module shares report helpers across scan modes"
)]

use super::{
    Context, Format, PARTITIONED_REPORT_SCHEMA_URI, PARTITIONED_REPORT_SCHEMA_VERSION, Path,
    Report, Result, ScanArgs, Store, Value, ViewArgs, Write, bail, fingerprint_hex, report,
};

/// Render the model in the requested format, to `--output` when given,
/// otherwise to `out`. Colour is used only for text going to a terminal.
pub(crate) fn write_report(args: &ScanArgs, out: &mut impl Write, model: &Report) -> Result<()> {
    write_report_options(
        ReportOutput {
            format: args.format,
            output: args.output.as_deref(),
            force: args.force,
            view: args.view,
            show_suppressed: args.show_suppressed,
            show_siblings: args.show_siblings,
            show_near_misses: args.show_near_misses,
            sort: args.sort.axis(),
            min_identifier_jaccard: args.min_identifier_jaccard,
        },
        out,
        model,
    )
}

/// Render a source report when supplemental artifact evidence could not be
/// loaded. The source verdict remains truthful, while text output omits the
/// now-invalid artifact follow-up guidance.
pub(crate) fn write_report_without_artifact_guidance(
    args: &ScanArgs,
    out: &mut impl Write,
    model: &Report,
) -> Result<()> {
    write_report_options_internal(
        ReportOutput {
            format: args.format,
            output: args.output.as_deref(),
            force: args.force,
            view: args.view,
            show_suppressed: args.show_suppressed,
            show_siblings: args.show_siblings,
            show_near_misses: args.show_near_misses,
            sort: args.sort.axis(),
            min_identifier_jaccard: args.min_identifier_jaccard,
        },
        out,
        model,
        false,
    )
}

/// Output choices shared by a freshly scanned and a recorded report.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independent presentation option mirrored by a CLI flag"
)]
#[derive(Clone, Copy)]
pub(crate) struct ReportOutput<'a> {
    /// Chosen serialization.
    pub(crate) format: Format,
    /// Optional destination instead of standard output.
    pub(crate) output: Option<&'a Path>,
    /// Whether an existing destination may be replaced.
    pub(crate) force: bool,
    /// How much of the text report to print, and in what colour.
    pub(crate) view: ViewArgs,
    /// Whether text output includes suppressed groups.
    pub(crate) show_suppressed: bool,
    /// Whether text output includes incomplete local mirrors.
    pub(crate) show_siblings: bool,
    /// Whether text output includes below-threshold LSH diagnostics.
    pub(crate) show_near_misses: bool,
    /// The axis the entries were put in order on, named in the listing's
    /// heading.
    pub(crate) sort: report::Sort,
    /// A floor on raw identifier agreement for the listing only.
    pub(crate) min_identifier_jaccard: Option<f64>,
}

/// Render a complete report with the common output path.
pub(crate) fn write_report_options(
    options: ReportOutput<'_>,
    out: &mut impl Write,
    model: &Report,
) -> Result<()> {
    write_report_options_internal(options, out, model, true)
}

/// Render a source report without artifact follow-up guidance after a
/// supplemental artifact read failed.
pub(crate) fn write_report_options_without_artifact_guidance(
    options: ReportOutput<'_>,
    out: &mut impl Write,
    model: &Report,
) -> Result<()> {
    write_report_options_internal(options, out, model, false)
}

fn write_report_options_internal(
    options: ReportOutput<'_>,
    out: &mut impl Write,
    model: &Report,
    include_artifact_guidance: bool,
) -> Result<()> {
    validate_presentation_options(
        options.format,
        options.show_suppressed,
        options.show_siblings,
        options.show_near_misses,
    )?;
    let text = match options.format {
        Format::Json => model.to_json().context("serializing the JSON report")?,
        Format::Sarif => model.to_sarif().context("serializing the SARIF report")?,
        Format::Text => {
            let mut buffer = Vec::new();
            model.render_text(text_options(&options), &mut buffer)?;
            String::from_utf8(buffer).context("rendering the text report")?
        }
    };
    match options.output {
        Some(path) => {
            write_output(path, text.as_bytes(), options.force)?;
            // Progress, not report: it would otherwise be the one line in a
            // redirected report's place on standard output.
            eprintln!("wrote {}", path.display());
        }
        None => out.write_all(text.as_bytes())?,
    }
    // After the report, and on the error stream: what qualifies a run is read
    // once the run's own answer has been, and a report being piped somewhere
    // still carries its warnings to the person who ran it.
    if options.format == Format::Text {
        out.flush()?;
        if include_artifact_guidance {
            model.render_notes(text_options(&options), &mut std::io::stderr())?;
        } else {
            model.render_notes_without_artifact_guidance(
                text_options(&options),
                &mut std::io::stderr(),
            )?;
        }
    }
    Ok(())
}

/// The text view the command-line options describe.
pub(crate) fn text_options(options: &ReportOutput<'_>) -> report::TextOptions {
    report::TextOptions {
        verbosity: options.view.verbose,
        quiet: options.view.quiet,
        limit: options.view.limit,
        color: options.view.color.enabled(options.output.is_none()),
        decoration: options.view.decoration.resolve(),
        show_suppressed: options.show_suppressed,
        show_siblings: options.show_siblings,
        show_near_misses: options.show_near_misses,
        sort: options.sort,
        min_identifier_jaccard: options.min_identifier_jaccard,
    }
}

/// Validate flags whose meaning exists only in the text presentation.
fn validate_presentation_options(
    format: Format,
    show_suppressed: bool,
    show_siblings: bool,
    show_near_misses: bool,
) -> Result<()> {
    if show_suppressed && format != Format::Text {
        bail!(
            "--show-suppressed applies only to text reports; JSON and SARIF always include suppressed groups"
        );
    }
    if show_siblings && format != Format::Text {
        bail!(
            "--show-siblings applies only to text reports; JSON and SARIF always include sibling data"
        );
    }
    if show_near_misses && format != Format::Text {
        bail!(
            "--show-near-misses applies only to text reports; JSON and SARIF always include near-miss data"
        );
    }
    Ok(())
}

fn write_output(path: &Path, text: &[u8], force: bool) -> Result<()> {
    if force {
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        return Ok(());
    }

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "writing {} (refusing to overwrite an existing file; pass --force to replace it)",
                path.display()
            )
        })?;
    file.write_all(text)
        .with_context(|| format!("writing {}", path.display()))
}

/// Restore how each group of a freshly recorded run relates to the run it was
/// compared with.
///
/// A scan cannot know this while it builds the report: continuity is decided
/// inside the store's write, by comparing member contents with the preceding
/// run. Reading it back afterwards is what lets one report distinguish a group
/// that kept its identity from one that inherited another group's history —
/// two outcomes of the same edit that otherwise read as unrelated events.
///
/// # Errors
///
/// Returns any underlying database error.
pub(crate) fn hydrate_group_identity(
    store: &Store,
    run_id: i64,
    predecessor_run: i64,
    groups: &mut [report::Group],
) -> Result<()> {
    let adoptions: std::collections::BTreeMap<_, _> = store
        .run_group_origins(run_id)?
        .into_iter()
        .filter_map(|origin| {
            origin
                .adopted_from
                .map(|parent| (origin.group_fingerprint_hex, parent))
        })
        .collect();
    let previous = store.run_group_fingerprints(predecessor_run)?;
    for group in groups {
        group.identity = if let Some(parent) = adoptions.get(&group.fingerprint) {
            Some(report::GroupIdentity {
                origin: report::IDENTITY_ADOPTED.to_string(),
                compared_with_run: predecessor_run,
                adopted_from: Some(parent.fingerprint_hex.clone()),
                shared_members: u64::try_from(parent.shared_content).ok(),
                // The population the shared count was taken out of, carried
                // only when the recorded edge measured one: a count paired
                // with a denominator from anywhere else would misstate the
                // evidence the connection was decided on.
                compared_members: parent
                    .compared_content
                    .and_then(|compared| u64::try_from(compared).ok()),
            })
        } else if previous.contains(&group.fingerprint) {
            Some(report::GroupIdentity {
                origin: report::IDENTITY_RETAINED.to_string(),
                compared_with_run: predecessor_run,
                adopted_from: None,
                shared_members: None,
                compared_members: None,
            })
        } else {
            // Nothing connects this group to the earlier run. Saying so about
            // every group of an unfamiliar tree would be the report's longest
            // and least informative column.
            None
        };
    }
    Ok(())
}

/// State what became of the highest-ranked groups of the run this one was
/// compared with.
///
/// Shares its rule with the per-group history: a group whose identity moved
/// to a successor did not close, so counting it as closed would report the
/// same edit as both a fix and a regression. Both runs are recorded, so this
/// is derived rather than stored, and a replayed report answers it the same
/// way the scan did.
///
/// # Errors
///
/// Returns any underlying database error.
pub(crate) fn top_group_churn(
    store: &Store,
    run_id: i64,
    predecessor_run: i64,
    top: usize,
) -> Result<report::TopChurn> {
    let previous_top = store.run_top_group_fingerprints(predecessor_run, top)?;
    let current_top = store.run_top_group_fingerprints(run_id, top)?;
    let current_all = store.run_group_fingerprints(run_id)?;
    let successors: std::collections::BTreeMap<_, _> = store
        .run_group_origins(run_id)?
        .into_iter()
        .filter_map(|origin| {
            origin
                .adopted_from
                .map(|parent| (origin.group_fingerprint_hex, parent.fingerprint_hex))
        })
        .collect();
    let inherited: std::collections::BTreeSet<_> = successors.values().cloned().collect();
    let previously_ranked: std::collections::BTreeSet<_> = previous_top.iter().cloned().collect();
    let currently_ranked: std::collections::BTreeSet<_> = current_top.iter().cloned().collect();
    // One pass, four buckets, every group of the earlier top in exactly one of
    // them: still ranked, ranked no longer, succeeded by another group, or
    // gone. A reader who counts one of them can reach the others.
    let mut still_ranked = Vec::new();
    let mut outranked = Vec::new();
    let mut superseded = Vec::new();
    let mut closed = Vec::new();
    for group in previous_top {
        if currently_ranked.contains(&group) {
            still_ranked.push(group);
        } else if current_all.contains(&group) {
            outranked.push(group);
        } else if inherited.contains(&group) {
            superseded.push(group);
        } else {
            closed.push(group);
        }
    }
    let mut entered = Vec::new();
    let mut promoted = Vec::new();
    for group in current_top {
        if previously_ranked.contains(&group) {
            continue;
        }
        if successors
            .get(&group)
            .is_some_and(|parent| previously_ranked.contains(parent))
        {
            promoted.push(group);
        } else {
            entered.push(group);
        }
    }
    Ok(report::TopChurn {
        since_run_id: predecessor_run,
        top: u64::try_from(top).unwrap_or(u64::MAX),
        closed,
        entered,
        still_ranked,
        outranked,
        superseded,
        promoted,
    })
}

/// Restore the artifact estimates that belong to a recorded source run.
///
/// The estimates are not part of the source snapshot because an artifact can
/// be analysed later. They are instead read into the single report model just
/// before every output format renders it.
pub(crate) fn hydrate_artifact_savings(
    store: &Store,
    run_id: i64,
    groups: &mut [report::Group],
) -> Result<()> {
    for group in groups {
        group.artifact_savings = store
            .clone_group_savings(run_id, &group.fingerprint)?
            .into_iter()
            .map(|(analysis_id, entry)| {
                Ok(report::ArtifactSavings {
                    artifact_analysis_id: analysis_id,
                    source_build_variant_fingerprint: fingerprint_hex(
                        entry.source_build_variant_fingerprint,
                    ),
                    artifact_build_variant_fingerprint: fingerprint_hex(
                        entry.artifact_build_variant_fingerprint,
                    ),
                    duplicated_bytes: entry.duplicated_bytes,
                    estimated_refactor_savings_bytes: entry.estimated_refactor_savings_bytes,
                    mapping_confidence: entry.mapping_confidence.to_string(),
                    clone_confidence: entry.clone_confidence,
                    model_confidence: entry.model_confidence.to_string(),
                    savings_confidence: entry.savings_confidence.to_string(),
                    model_schema_version: entry.model_schema_version,
                    assumptions: serde_json::from_str(&entry.assumptions_json)
                        .context("parsing persisted artifact savings assumptions")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
    }
    Ok(())
}

/// Render independent semantic reports without inventing a combined variant.
///
/// A compilation database can describe several programs in one source tree.
/// JSON therefore names every report under `partitions`; text separates whole
/// reports, and SARIF joins its standard `runs` array. None of those sums
/// findings or coverage across different build variants.
pub(crate) fn write_partitioned_reports(
    args: &ScanArgs,
    out: &mut impl Write,
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_variant_not_run: Option<&report::CrossVariantComparisonNotRun>,
    cross_language: Option<&report::CrossLanguageComparison>,
    cross_language_not_run: Option<&report::CrossLanguageComparisonNotRun>,
) -> Result<()> {
    write_partitioned_reports_internal(
        args,
        out,
        models,
        cross_variant,
        cross_variant_not_run,
        cross_language,
        cross_language_not_run,
        true,
    )
}

/// Render partitioned source reports while suppressing artifact follow-up
/// guidance after supplemental hydration failed.
pub(crate) fn write_partitioned_reports_without_artifact_guidance(
    args: &ScanArgs,
    out: &mut impl Write,
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_variant_not_run: Option<&report::CrossVariantComparisonNotRun>,
    cross_language: Option<&report::CrossLanguageComparison>,
    cross_language_not_run: Option<&report::CrossLanguageComparisonNotRun>,
) -> Result<()> {
    write_partitioned_reports_internal(
        args,
        out,
        models,
        cross_variant,
        cross_variant_not_run,
        cross_language,
        cross_language_not_run,
        false,
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the public partitioned-report shape is mirrored while only the guidance policy varies"
)]
fn write_partitioned_reports_internal(
    args: &ScanArgs,
    out: &mut impl Write,
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_variant_not_run: Option<&report::CrossVariantComparisonNotRun>,
    cross_language: Option<&report::CrossLanguageComparison>,
    cross_language_not_run: Option<&report::CrossLanguageComparisonNotRun>,
    include_artifact_guidance: bool,
) -> Result<()> {
    validate_presentation_options(
        args.format,
        args.show_suppressed,
        args.show_siblings,
        args.show_near_misses,
    )?;
    if let ([model], None, None, None, None) = (
        models,
        cross_variant,
        cross_variant_not_run,
        cross_language,
        cross_language_not_run,
    ) {
        return if include_artifact_guidance {
            write_report(args, out, model)
        } else {
            write_report_without_artifact_guidance(args, out, model)
        };
    }
    let text = match args.format {
        Format::Json => partitioned_json(
            models,
            cross_variant,
            cross_variant_not_run,
            cross_language,
            cross_language_not_run,
        )?,
        Format::Sarif => partitioned_sarif(
            models,
            cross_variant,
            cross_variant_not_run,
            cross_language,
            cross_language_not_run,
        )?,
        Format::Text => partitioned_text(
            args,
            models,
            cross_variant,
            cross_variant_not_run,
            cross_language,
            cross_language_not_run,
        )?,
    };
    write_partitioned_text(args, out, &text)?;
    // After the reports, and on the error stream, for the same reason one
    // report's notes are: they qualify a run rather than answering it.
    if args.format == Format::Text {
        out.flush()?;
        let options = partition_text_options(args);
        for model in models {
            model.render_notes_without_artifact_guidance(options, &mut std::io::stderr())?;
        }
        if include_artifact_guidance && !options.quiet {
            report::render_partition_artifact_guidance(models, &mut std::io::stderr())?;
        }
    }
    Ok(())
}

/// The text view a partitioned scan renders every partition under.
fn partition_text_options(args: &ScanArgs) -> report::TextOptions {
    text_options(&ReportOutput {
        format: args.format,
        output: args.output.as_deref(),
        force: args.force,
        view: args.view,
        show_suppressed: args.show_suppressed,
        show_siblings: args.show_siblings,
        show_near_misses: args.show_near_misses,
        sort: args.sort.axis(),
        min_identifier_jaccard: args.min_identifier_jaccard,
    })
}

pub(super) fn partitioned_json(
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_variant_not_run: Option<&report::CrossVariantComparisonNotRun>,
    cross_language: Option<&report::CrossLanguageComparison>,
    cross_language_not_run: Option<&report::CrossLanguageComparisonNotRun>,
) -> Result<String> {
    let mut value = serde_json::Map::new();
    value.insert(
        "schema_version".to_string(),
        serde_json::json!(PARTITIONED_REPORT_SCHEMA_VERSION),
    );
    value.insert(
        "$schema".to_string(),
        serde_json::json!(PARTITIONED_REPORT_SCHEMA_URI),
    );
    value.insert("partitions".to_string(), serde_json::json!(models));
    if let Some(comparison) = cross_variant {
        value.insert(
            "cross_variant_comparison".to_string(),
            serde_json::json!(comparison),
        );
    }
    if let Some(status) = cross_variant_not_run {
        value.insert(
            "cross_variant_comparison_status".to_string(),
            serde_json::json!(status),
        );
    }
    if let Some(comparison) = cross_language {
        value.insert(
            "cross_language_comparison".to_string(),
            serde_json::json!(comparison),
        );
    }
    if let Some(status) = cross_language_not_run {
        value.insert(
            "cross_language_comparison_status".to_string(),
            serde_json::json!(status),
        );
    }
    serde_json::to_string_pretty(&Value::Object(value))
        .context("serializing partitioned JSON reports")
}

pub(super) fn partitioned_sarif(
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_variant_not_run: Option<&report::CrossVariantComparisonNotRun>,
    cross_language: Option<&report::CrossLanguageComparison>,
    cross_language_not_run: Option<&report::CrossLanguageComparisonNotRun>,
) -> Result<String> {
    let mut runs = Vec::new();
    let root = models.first().map_or(".", |model| model.run.root.as_str());
    for model in models {
        let log: Value = serde_json::from_str(
            &model
                .to_sarif()
                .context("serializing a partitioned SARIF report")?,
        )
        .context("reading a partitioned SARIF report")?;
        if let Some(mut contained) = log.get("runs").and_then(Value::as_array).cloned() {
            runs.append(&mut contained);
        }
    }
    if let Some(comparison) = cross_variant {
        runs.push(cross_variant_sarif_run(comparison, root));
    }
    if let Some(status) = cross_variant_not_run {
        runs.push(cross_variant_not_run_sarif_run(status, root));
    }
    if let Some(comparison) = cross_language {
        runs.push(cross_language_sarif_run(comparison, root));
    }
    if let Some(status) = cross_language_not_run {
        runs.push(cross_language_not_run_sarif_run(status, root));
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "version": report::sarif::SARIF_VERSION,
        "$schema": report::sarif::SARIF_SCHEMA_URI,
        "runs": runs,
    }))
    .context("serializing partitioned SARIF reports")
}

pub(super) fn cross_variant_sarif_run(
    comparison: &report::CrossVariantComparison,
    root: &str,
) -> Value {
    serde_json::json!({
        "tool": { "driver": {
            "name": "codehelion", "version": env!("CARGO_PKG_VERSION"),
            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": [{
                "id": "comparison/cross-build-variant-exact",
                "name": "CrossBuildVariantExactClone",
                "shortDescription": { "text": "Exact clone across build variants" }
            }]
        }},
        "automationDetails": { "id": "codehelion/cross-build-variants" },
        "originalUriBaseIds": comparison_uri_bases(root),
        "results": comparison.groups.iter().map(cross_variant_sarif_result).collect::<Vec<_>>(),
        "properties": { "crossVariantComparison": comparison }
    })
}

/// A separate SARIF run preserves the distinction between an empty comparison
/// and one that could not be evaluated at all.
fn cross_variant_not_run_sarif_run(
    status: &report::CrossVariantComparisonNotRun,
    root: &str,
) -> Value {
    serde_json::json!({
        "tool": { "driver": {
            "name": "codehelion", "version": env!("CARGO_PKG_VERSION"),
            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": [{
                "id": "comparison/cross-build-variant-exact",
                "name": "CrossBuildVariantExactClone",
                "shortDescription": { "text": "Exact clone across build variants" }
            }]
        }},
        "automationDetails": { "id": "codehelion/cross-build-variants" },
        "originalUriBaseIds": comparison_uri_bases(root),
        "results": [],
        "properties": { "crossVariantComparisonStatus": status }
    })
}

fn cross_variant_sarif_result(group: &report::CrossVariantGroup) -> Value {
    serde_json::json!({
        "ruleId": "comparison/cross-build-variant-exact", "level": "note",
        "message": { "text": "Exact Type-1 clone across independent build variants" },
        "partialFingerprints": { "crossVariantGroupFingerprint/v1": group.id },
        "locations": group.members.first().map(cross_variant_sarif_location).into_iter().collect::<Vec<_>>(),
        "relatedLocations": group.members.iter().map(cross_variant_sarif_location).collect::<Vec<_>>()
    })
}

fn cross_variant_sarif_location(member: &report::CrossVariantMember) -> Value {
    serde_json::json!({
        "physicalLocation": { "artifactLocation": {
                "uri": report::sarif::uri_reference(&member.file),
                "uriBaseId": report::sarif::SRCROOT
            },
            "region": { "startLine": member.start_line, "endLine": member.end_line } },
        "properties": { "originVariant": member.origin_variant }
    })
}

fn cross_language_sarif_run(comparison: &report::CrossLanguageComparison, root: &str) -> Value {
    serde_json::json!({
        "tool": { "driver": {
            "name": "codehelion", "version": env!("CARGO_PKG_VERSION"),
            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": [{
                "id": "comparison/cross-language-semantic",
                "name": "CrossLanguageRestrictedSemantic",
                "shortDescription": { "text": "Registered Rust-to-C++ semantic pipeline" }
            }]
        }},
        "automationDetails": { "id": "codehelion/cross-language" },
        "originalUriBaseIds": comparison_uri_bases(root),
        "results": comparison.groups.iter().map(cross_language_sarif_result).collect::<Vec<_>>(),
        "properties": { "crossLanguageComparison": comparison }
    })
}

fn cross_language_not_run_sarif_run(
    status: &report::CrossLanguageComparisonNotRun,
    root: &str,
) -> Value {
    serde_json::json!({
        "tool": { "driver": {
            "name": "codehelion", "version": env!("CARGO_PKG_VERSION"),
            "semanticVersion": env!("CARGO_PKG_VERSION"), "rules": [{
                "id": "comparison/cross-language-semantic",
                "name": "CrossLanguageRestrictedSemantic",
                "shortDescription": { "text": "Registered Rust-to-C++ semantic pipeline" }
            }]
        }},
        "automationDetails": { "id": "codehelion/cross-language" },
        "originalUriBaseIds": comparison_uri_bases(root),
        "results": [],
        "properties": { "crossLanguageComparisonStatus": status }
    })
}

fn cross_language_sarif_result(group: &report::CrossLanguageGroup) -> Value {
    serde_json::json!({
        "ruleId": "comparison/cross-language-semantic", "level": "note",
        "message": { "text": format!("Registered cross-language semantic rule {}", group.rule_id) },
        "partialFingerprints": { "crossLanguageGroupFingerprint/v1": group.id },
        "locations": group.members.first().map(cross_language_sarif_location).into_iter().collect::<Vec<_>>(),
        "relatedLocations": group.members.iter().map(cross_language_sarif_location).collect::<Vec<_>>(),
        "properties": {
            "ruleVersion": group.rule_version,
            "semanticConfidence": group.semantic_confidence,
            "correspondenceIds": group.correspondence_ids,
        }
    })
}

fn cross_language_sarif_location(member: &report::CrossLanguageMember) -> Value {
    serde_json::json!({
        "physicalLocation": { "artifactLocation": {
                "uri": report::sarif::uri_reference(&member.file),
                "uriBaseId": report::sarif::SRCROOT
            },
            "region": { "startLine": member.start_line, "endLine": member.end_line } },
        "properties": { "originVariant": member.origin_variant, "language": member.language }
    })
}

/// URI base map shared by every comparison-only SARIF run.
fn comparison_uri_bases(root: &str) -> Value {
    let mut bases = serde_json::Map::new();
    bases.insert(
        report::sarif::SRCROOT.to_string(),
        serde_json::json!({ "uri": report::sarif::root_uri(root) }),
    );
    Value::Object(bases)
}

pub(super) fn partitioned_text(
    args: &ScanArgs,
    models: &[Report],
    cross_variant: Option<&report::CrossVariantComparison>,
    cross_variant_not_run: Option<&report::CrossVariantComparisonNotRun>,
    cross_language: Option<&report::CrossLanguageComparison>,
    cross_language_not_run: Option<&report::CrossLanguageComparisonNotRun>,
) -> Result<String> {
    let options = partition_text_options(args);
    let mut rendered = Vec::new();
    for model in models {
        writeln!(
            &mut rendered,
            "{}",
            partition_heading(&model.run.build_variant)
        )?;
        model.render_text(options, &mut rendered)?;
        rendered.extend_from_slice(b"\n\n");
    }
    let mut text = String::from_utf8(rendered).context("rendering partitioned text reports")?;
    if let Some(comparison) = cross_variant {
        append_cross_variant_text(&mut text, comparison)?;
    }
    if let Some(status) = cross_variant_not_run {
        append_cross_variant_not_run_text(&mut text, status)?;
    }
    if let Some(comparison) = cross_language {
        if cross_variant.is_some() || cross_variant_not_run.is_some() {
            text.push('\n');
        }
        append_cross_language_text(&mut text, comparison)?;
    }
    if let Some(status) = cross_language_not_run {
        if cross_variant.is_some() || cross_variant_not_run.is_some() || cross_language.is_some() {
            text.push('\n');
        }
        append_cross_language_not_run_text(&mut text, status)?;
    }
    Ok(text)
}

/// A stable, human-readable boundary between independently analysed builds.
pub(super) fn partition_heading(variant: &report::BuildVariantInfo) -> String {
    let languages = if variant.languages.is_empty() {
        "none".to_string()
    } else {
        variant.languages.join(", ")
    };
    format!(
        "Build variant {} (mode: {}; languages: {languages})",
        variant.fingerprint, variant.mode
    )
}

fn append_cross_variant_text(
    text: &mut String,
    comparison: &report::CrossVariantComparison,
) -> Result<()> {
    use std::fmt::Write as _;
    writeln!(
        text,
        "Cross-build-variant comparison (exact Type-1 units only)"
    )?;
    writeln!(text, "policy: {}", comparison.policy_version)?;
    writeln!(text, "comparison: {}", comparison.comparison_id)?;
    writeln!(
        text,
        "origin variants: {}",
        comparison.origin_variants.join(", ")
    )?;
    for group in &comparison.groups {
        writeln!(text, "  {} ({})", group.id, group.clone_type)?;
        for member in &group.members {
            writeln!(
                text,
                "    [{}] {}:{}-{}",
                member.origin_variant, member.file, member.start_line, member.end_line
            )?;
        }
    }
    Ok(())
}

/// Say why an explicit comparison was not attempted instead of leaving a
/// caller to infer it from the absence of a comparison section.
fn append_cross_variant_not_run_text(
    text: &mut String,
    status: &report::CrossVariantComparisonNotRun,
) -> Result<()> {
    use std::fmt::Write as _;
    writeln!(text, "Cross-build-variant comparison was not run")?;
    writeln!(text, "reason: {}", status.reason)?;
    writeln!(
        text,
        "origin variants available: {}",
        if status.origin_variants.is_empty() {
            "none".to_string()
        } else {
            status.origin_variants.join(", ")
        }
    )?;
    Ok(())
}

fn append_cross_language_text(
    text: &mut String,
    comparison: &report::CrossLanguageComparison,
) -> Result<()> {
    use std::fmt::Write as _;
    writeln!(
        text,
        "Cross-language comparison (registered semantic pipelines only)"
    )?;
    writeln!(text, "policy: {}", comparison.policy_version)?;
    writeln!(text, "comparison: {}", comparison.comparison_id)?;
    writeln!(
        text,
        "origin variants: {}",
        comparison.origin_variants.join(", ")
    )?;
    if comparison.search_truncated {
        writeln!(
            text,
            "warning: {}",
            report::search_truncation_note(&comparison.funnel)
        )?;
    }
    for group in &comparison.groups {
        writeln!(
            text,
            "  {} ({} v{}, confidence {:.2})",
            group.id, group.rule_id, group.rule_version, group.semantic_confidence
        )?;
        writeln!(
            text,
            "    Correspondences: {}",
            group.correspondence_ids.join(", ")
        )?;
        for member in &group.members {
            writeln!(
                text,
                "    [{} {}] {}:{}-{}",
                member.origin_variant,
                member.language,
                member.file,
                member.start_line,
                member.end_line
            )?;
        }
    }
    Ok(())
}

fn append_cross_language_not_run_text(
    text: &mut String,
    status: &report::CrossLanguageComparisonNotRun,
) -> Result<()> {
    use std::fmt::Write as _;
    writeln!(text, "Cross-language comparison was not run")?;
    writeln!(text, "reason: {}", status.reason)?;
    writeln!(
        text,
        "origin variants available: {}",
        if status.origin_variants.is_empty() {
            "none".to_string()
        } else {
            status.origin_variants.join(", ")
        }
    )?;
    Ok(())
}

fn write_partitioned_text(args: &ScanArgs, out: &mut impl Write, text: &str) -> Result<()> {
    match args.output.as_deref() {
        Some(path) => {
            write_output(path, text.as_bytes(), args.force)?;
            eprintln!("wrote {}", path.display());
        }
        None => out.write_all(text.as_bytes())?,
    }
    Ok(())
}
