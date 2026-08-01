//! Human-readable scan report rendering.

use super::{
    ArtifactSavings, BASELINE_COMPARE, BaselineStatus, GONE_LISTED, GROUP_EXPANDED, GROUP_NEW,
    Group, Report, SCOPE_FRAGMENT, Summary, TEXT_GROUP_LIMIT, TEXT_MEMBER_LIMIT, TextOptions,
    UnusedRule, Write, budget_note, depth_truncation_files, duplicated_tokens, io,
    search_truncation_note, severed_note,
};

/// Minimal ANSI styling, disabled when the output is not a terminal.
pub(super) struct Palette {
    pub(super) enabled: bool,
}

impl Palette {
    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
    }
}

impl Report {
    /// The report as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Render the human-readable text view.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, opts: TextOptions, out: &mut impl Write) -> io::Result<()> {
        let palette = Palette {
            enabled: opts.color,
        };
        self.render_summary(&palette, out)?;
        if opts.verbose {
            self.render_funnel(&palette, out)?;
        }
        self.render_groups(opts, &palette, out)
    }

    /// The stage-by-stage pass counts, wide enough to be read as a column.
    fn render_funnel(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        if self.summary.funnel.is_empty() {
            return Ok(());
        }
        let width = self
            .summary
            .funnel
            .iter()
            .map(|stage| stage.stage.len())
            .max()
            .unwrap_or(0);
        writeln!(out)?;
        writeln!(out, "{}", palette.bold("candidate pipeline:"))?;
        for stage in &self.summary.funnel {
            write!(out, "  {:width$}  {}", stage.stage, stage.passed)?;
            if !stage.dropped.is_empty() {
                let causes: Vec<String> = stage
                    .dropped
                    .iter()
                    .map(|drop| format!("{} {}", drop.label(), drop.count))
                    .collect();
                write!(out, "  (dropped: {})", causes.join(", "))?;
            }
            writeln!(out)?;
        }
        Ok(())
    }

    /// What the scan read: how much, what was left out, and what moved since
    /// the last time. Everything here is about the input, before a single
    /// group is mentioned.
    fn render_inputs(&self, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "  files: {} analysed (rust {}, c {}, cpp {})",
            summary.files.total, summary.files.rust, summary.files.c, summary.files.cpp,
        )?;
        // Which grammar read the bare `.h` headers decides what the analysis
        // could see in them, so a run that read any says so rather than
        // leaving the reader to infer it from the language counts.
        if summary.files.c + summary.files.cpp > 0
            && let Some(headers) = &self.run.build_variant.headers
        {
            writeln!(out, "    bare .h headers read as {headers}")?;
        }
        writeln!(
            out,
            "  excluded: {} generated, {} by glob, {} too large, {} binary, {} unreadable, {} symlinks, {} walk errors, {} timed out ({} total)",
            summary.excluded.generated,
            summary.excluded.by_glob,
            summary.excluded.too_large,
            summary.excluded.binary,
            summary.excluded.unreadable,
            summary.excluded.symlinks,
            summary.excluded.walk_errors,
            summary.excluded.timed_out,
            summary.excluded.skipped,
        )?;
        writeln!(
            out,
            "  lines: {}; tokens: {}; lexer diagnostics: {}",
            summary.lines, summary.tokens, summary.lexer_diagnostics,
        )?;
        // Before anything about what was found, because it is the sentence
        // that says how to read everything after it.
        if let Some(guardrails) = &summary.guardrails {
            writeln!(
                out,
                "  {} profile: files over {} bytes skipped, {} ms per file, {} ms helper deadline, posting lists up to {}, {} candidate pairs per pass, {} units per group",
                guardrails.profile,
                guardrails.max_file_bytes,
                guardrails.parse_timeout_ms,
                guardrails.helper_timeout_ms,
                guardrails.posting_cap,
                guardrails.pair_budget,
                guardrails.max_component,
            )?;
        }
        // Beside the ceilings, and for the same reason: it says how much of
        // what follows was decided by a compiler and how much was not.
        if let Some(compiler) = &summary.compiler {
            writeln!(
                out,
                "  compiler: answered for {} files, {} not asked, {} unanswered{}",
                compiler.answered,
                compiler.not_asked,
                compiler.unavailable.values().sum::<u64>(),
                if compiler.restarts == 0 {
                    String::new()
                } else {
                    format!(" (helper restarted {} time(s))", compiler.restarts)
                },
            )?;
            for (reason, count) in &compiler.unavailable {
                writeln!(out, "    {count} {reason}")?;
            }
            for refusal in &compiler.execution_refusals {
                writeln!(out, "    {} file(s): {}", refusal.files, refusal.message)?;
            }
        }
        if let Some(baseline) = &summary.baseline {
            writeln!(
                out,
                "  baseline {}: {} of {} entries matched, {} no longer found",
                baseline.file, baseline.matched, baseline.entries, baseline.stale,
            )?;
            // The same counts said as a before and an after, which is the
            // question somebody working duplication down is asking.
            writeln!(
                out,
                "    since it was recorded: {} gone (-{} repeated tokens), {} new (+{}), \
                 {} expanded (+{} occurrence(s), +{} repeated tokens), {} unchanged",
                baseline.stale,
                baseline.stale_tokens,
                baseline.appeared,
                baseline.appeared_tokens,
                baseline.expanded,
                baseline.expanded_instances,
                baseline.expanded_tokens,
                baseline.matched.saturating_sub(baseline.expanded),
            )?;
            render_gone(baseline, out)?;
        }
        Ok(())
    }

    fn render_summary(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "{}",
            palette.bold(&format!("codehelion scan ({} mode)", self.run.mode))
        )?;
        writeln!(out, "  root: {}", self.run.root)?;
        self.render_configuration(out)?;
        self.render_inputs(out)?;
        // A recovering parser reports no failure, so the share it could not
        // follow is the only thing separating "little duplication here" from
        // "most of this was never read".
        if let Some(unparsed) = &summary.unparsed
            && unparsed.files > 0
        {
            writeln!(
                out,
                "    the parser could not follow {:.2}% of the tokens, over {} of {} files",
                unparsed.share * 100.0,
                unparsed.files,
                summary.files.total,
            )?;
        }
        writeln!(
            out,
            "  clone groups: {} (type-1 {}, type-2 {}, type-3 {}, restricted-semantic {}; suppressed: {} noise, {} by rule)",
            summary.groups.total,
            summary.groups.type_1,
            summary.groups.type_2,
            summary.groups.type_3,
            summary.groups.restricted_semantic,
            summary.suppressed.noise,
            summary.suppressed.by_rule,
        )?;
        let runs = &summary.groups;
        if runs.fragment_scope > 0 || runs.folded_runs > 0 || runs.subsumed_runs > 0 {
            writeln!(
                out,
                "    {} of them are runs duplicated inside units that are not clones of each \
                 other; {} more were folded into the groups that already cover them and {} \
                 into longer runs",
                runs.fragment_scope, runs.folded_runs, runs.subsumed_runs,
            )?;
        }
        // Hidden without anybody asking, so the report says it happened and
        // says how to undo it.
        if summary.suppressed.vendored > 0 {
            writeln!(
                out,
                "    {} of them are duplication inside vendored trees, which this project does \
                 not write; --include-vendored reports them",
                summary.suppressed.vendored,
            )?;
        }
        if summary.groups.test_code > 0 {
            writeln!(
                out,
                "    {} of them are duplication inside test code, which repeats itself by \
                 design; a group spanning a test and what it exercises is not counted here",
                summary.groups.test_code,
            )?;
        }
        // The database keeps one scan, so printing a run number would advertise
        // a history that is not there. What a reader needs instead is where the
        // snapshot went and how to compare it with an earlier one.
        writeln!(
            out,
            "  snapshot: {} (one scan at a time; compare with an earlier scan through a baseline)",
            self.run.database
        )?;
        if !summary.unused_suppressions.is_empty() {
            let names: Vec<String> = summary
                .unused_suppressions
                .iter()
                .map(UnusedRule::label)
                .collect();
            writeln!(
                out,
                "  note: {} suppression rule(s) matched nothing: {}",
                summary.unused_suppressions.len(),
                names.join(", "),
            )?;
        }
        render_unapplied_suppression_policies(summary, out)?;
        if summary.split_components > 0 {
            writeln!(
                out,
                "  note: {} set(s) of related units were too large to compare as one and were \
                 cut; clones of each other may be reported as separate groups{}",
                summary.split_components,
                severed_note(&summary.funnel),
            )?;
        }
        if summary.search_truncated {
            writeln!(out, "{}", search_truncation_note(&summary.funnel))?;
        }
        if summary.pair_budget_exhausted {
            writeln!(out, "{}", budget_note(&summary.funnel))?;
        }
        if let Some(files) = depth_truncation_files(&summary.funnel) {
            writeln!(
                out,
                "  note: structural parsing reached its depth limit in {files} file(s); the deepest region of each was left out of analysis"
            )?;
        }
        Ok(())
    }

    fn render_configuration(&self, out: &mut impl Write) -> io::Result<()> {
        let configuration = &self.run.configuration;
        if let Some(path) = &configuration.path {
            writeln!(
                out,
                "  configuration: {} ({path}); minimum clone length: {} tokens",
                configuration.source, configuration.min_clone_tokens,
            )
        } else {
            writeln!(
                out,
                "  configuration: {}; minimum clone length: {} tokens",
                configuration.source, configuration.min_clone_tokens,
            )
        }
    }

    fn render_groups(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let reported: Vec<&Group> = self
            .groups
            .iter()
            .filter(|group| group.suppressed.is_none())
            .collect();
        let visible: Vec<&Group> = reported
            .iter()
            .copied()
            .filter(|group| {
                opts.min_identifier_jaccard.is_none_or(|floor| {
                    group
                        .identifier_jaccard
                        .is_some_and(|measured| measured >= floor)
                })
            })
            .collect();
        if !visible.is_empty() {
            let limit = if opts.verbose {
                visible.len()
            } else {
                TEXT_GROUP_LIMIT
            };
            writeln!(out)?;
            writeln!(
                out,
                "{}",
                palette.bold(&format!("top groups by {}:", opts.sort.name()))
            )?;
            for group in visible.iter().take(limit) {
                render_group(group, opts, palette, out)?;
                if opts.show_siblings {
                    self.render_siblings(group, out)?;
                }
            }
            if visible.len() > limit {
                writeln!(out, "  ... and {} more groups", visible.len() - limit)?;
            }
        }
        // A floor that quietly swallowed the unmeasured, or the listing that
        // came out of it, would read as "there is nothing else". Said after
        // the listing because it qualifies what was just read.
        if let Some(floor) = opts.min_identifier_jaccard
            && reported.len() > visible.len()
        {
            writeln!(out)?;
            writeln!(
                out,
                "  {} group(s) are not listed: raw identifier agreement below {floor:.2}, or not \
                 measured in this mode",
                reported.len() - visible.len(),
            )?;
        }

        if opts.show_suppressed {
            let suppressed: Vec<&Group> = self
                .groups
                .iter()
                .filter(|group| group.suppressed.is_some())
                .collect();
            if !suppressed.is_empty() {
                writeln!(out)?;
                writeln!(out, "{}", palette.bold("suppressed groups:"))?;
                let limit = if opts.verbose {
                    suppressed.len()
                } else {
                    TEXT_GROUP_LIMIT
                };
                for group in suppressed.iter().take(limit) {
                    render_group(group, opts, palette, out)?;
                    if opts.show_siblings {
                        self.render_siblings(group, out)?;
                    }
                }
                if suppressed.len() > limit {
                    writeln!(
                        out,
                        "  ... and {} more suppressed groups",
                        suppressed.len() - limit
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Render local incomplete mirrors only when the text caller requested
    /// them. JSON and SARIF retain the data unconditionally.
    fn render_siblings(&self, group: &Group, out: &mut impl Write) -> io::Result<()> {
        let Some(siblings) = self
            .siblings
            .iter()
            .find(|siblings| siblings.group_fingerprint == group.fingerprint)
        else {
            return Ok(());
        };
        for sibling in &siblings.siblings {
            let member = &sibling.member;
            writeln!(
                out,
                "    sibling {} {} ({:.2}): {}:{}{}",
                sibling.clone_type,
                sibling.confidence_band,
                sibling.similarity.composite,
                member.file,
                member.start_line,
                member
                    .unit
                    .as_deref()
                    .map(|unit| format!(" ({unit})"))
                    .unwrap_or_default(),
            )?;
        }
        Ok(())
    }
}

/// Explain that a Fast report did not classify policy categories rather than
/// implying that their configured policies applied and matched nothing.
fn render_unapplied_suppression_policies(
    summary: &Summary,
    out: &mut impl Write,
) -> io::Result<()> {
    if !summary.unapplied_suppression_policies.is_empty() {
        writeln!(
            out,
            "  note: Fast mode did not apply suppression policies that require structural classifications: {}; run with --mode structural or --mode semantic to apply them",
            summary.unapplied_suppression_policies.join(", "),
        )?;
    }
    Ok(())
}

/// List what the baseline froze that this run no longer reports.
///
/// Only in compare mode: suppress mode is being asked to hide known
/// duplication, and a list of duplication that is no longer there is not what
/// it was asked for. The JSON report carries the list either way.
fn render_gone(baseline: &BaselineStatus, out: &mut impl Write) -> io::Result<()> {
    if baseline.mode != BASELINE_COMPARE || baseline.gone.is_empty() {
        return Ok(());
    }
    for entry in baseline.gone.iter().take(GONE_LISTED) {
        let anchor = entry.anchor.as_ref().map_or_else(String::new, |anchor| {
            let unit = anchor
                .unit
                .as_deref()
                .map_or_else(String::new, |name| format!(" in {name}"));
            format!(
                ", last seen at {}:{}{}",
                anchor.file, anchor.start_line, unit
            )
        });
        writeln!(
            out,
            "      gone {} {} ({} repeated tokens){}",
            entry.group, entry.clone_type, entry.duplicated_tokens, anchor,
        )?;
    }
    // A truncated list that does not say it was truncated reads as the whole
    // answer.
    if let Some(rest) = baseline.gone.len().checked_sub(GONE_LISTED)
        && rest > 0
    {
        writeln!(
            out,
            "      and {rest} more not listed here; the JSON report has all of them",
        )?;
    }
    Ok(())
}

/// Say where a group stands relative to the baseline the run was given.
///
/// Only new and expanded groups get a line. "Continuing" is the unremarkable
/// case and marking every one of them would bury the changes that matter.
fn render_group_baseline(group: &Group, out: &mut impl Write) -> io::Result<()> {
    let Some(baseline) = &group.baseline else {
        return Ok(());
    };
    match baseline.state.as_str() {
        GROUP_NEW => match &baseline.derived_from {
            Some(derived) => writeln!(
                out,
                "    new since the baseline, standing where {} stood ({} occurrence(s) in the \
                 same place)",
                derived.group, derived.shared_sites,
            ),
            None => writeln!(out, "    new since the baseline"),
        },
        GROUP_EXPANDED => writeln!(
            out,
            "    expanded since the baseline: {} new occurrence(s)",
            baseline.added_instances.unwrap_or(0),
        ),
        _ => Ok(()),
    }
}

/// Render one group: the priority with its inputs spelled out, then its
/// members. The non-verbose view truncates long member lists with an
/// explicit count, never silently.
pub(super) fn render_group(
    group: &Group,
    opts: TextOptions,
    palette: &Palette,
    out: &mut impl Write,
) -> io::Result<()> {
    // A group that is shown but ranked down says why: its place in the
    // ranking is explained rather than silently lowered.
    let marker = match (&group.suppressed, &group.boilerplate, group.test_code) {
        (Some(cause), _, _) => format!(
            " {}",
            palette.yellow(&format!("[suppressed: {}]", cause.label()))
        ),
        (None, Some(category), _) => {
            format!(" {}", palette.yellow(&format!("[boilerplate: {category}]")))
        }
        (None, None, true) => format!(" {}", palette.yellow("[test code]")),
        (None, None, false) => String::new(),
    };
    // A pair reported on its own is the one kind of finding whose members
    // turn up in other findings too. Saying so is what stops it reading as a
    // second, contradictory account of the same code.
    let overlap = if group.split_pair {
        format!(" {}", palette.yellow("[pair no group holds]"))
    } else {
        String::new()
    };
    // A fragment-scope group states its extent: without it "type-1, 40
    // tokens" reads as a duplicated unit, which it is not.
    let scope = match (group.scope.as_str(), group.statements) {
        (SCOPE_FRAGMENT, Some(statements)) => format!(" run of {statements} statements"),
        (SCOPE_FRAGMENT, None) => " run".to_string(),
        _ => String::new(),
    };
    let priority = &group.priority;
    let spread = match (priority.inputs.files, priority.inputs.directories) {
        (0 | 1, _) => "within one file",
        (_, 0 | 1) => "within one directory",
        _ => "across directories",
    };
    // Raw identifier agreement sits on the heading rather than inside the
    // list of ranking inputs: it is the measure that most often decides
    // whether a group is worth opening, and it was unreadable buried among
    // seven other numbers.
    let identifiers = group.identifier_jaccard.map_or_else(
        || " identifiers n/a".to_string(),
        |value| format!(" identifiers {value:.2}"),
    );
    writeln!(
        out,
        "  {} {}{scope} priority {:.2}{identifiers} [{spread}]{overlap}{marker}",
        palette.cyan(&group.fingerprint),
        group.clone_type,
        priority.value,
    )?;
    render_group_baseline(group, out)?;
    // The composed number is never shown on its own: the three measures that
    // made it say why the finding is where it is, and disagreeing with the
    // placement means disagreeing with one of them.
    writeln!(
        out,
        "    confidence {:.2}, maintenance risk {:.2}, refactoring difficulty {:.2} \
         ({} instances, {}-{} tokens, {} repeated, {:.2} similarity, {} file(s))",
        priority.clone_confidence,
        priority.maintenance_risk,
        priority.refactoring_difficulty,
        priority.inputs.instances,
        priority.inputs.smallest_member_tokens,
        priority.inputs.largest_member_tokens,
        duplicated_tokens(group),
        priority.inputs.similarity,
        priority.inputs.files,
    )?;
    if let Some(similarity) = &group.similarity {
        writeln!(out, "    {}", similarity.line())?;
    }
    writeln!(out, "    content entropy: {:.2} bits", group.entropy_bits)?;
    if let Some(body) = group.body_materiality {
        writeln!(
            out,
            "    body evidence: loop {}, recognised allocation {}, at least {} call site(s)",
            if body.has_loop { "yes" } else { "no" },
            if body.has_dynamic_allocation {
                "yes"
            } else {
                "no"
            },
            body.call_count,
        )?;
    }
    render_artifact_savings(&group.artifact_savings, out)?;
    let limit = if opts.verbose {
        group.members.len()
    } else {
        TEXT_MEMBER_LIMIT
    };
    for member in group.members.iter().take(limit) {
        let unit = member.unit.as_deref().map_or_else(
            || " [no enclosing unit]".to_string(),
            |name| format!(" ({name})"),
        );
        let canonical = if member.canonical { " [canonical]" } else { "" };
        writeln!(
            out,
            "    {}:{}-{}{unit}{canonical} [finding {}]",
            member.file, member.start_line, member.end_line, member.finding_id,
        )?;
    }
    if group.members.len() > limit {
        writeln!(
            out,
            "    ... and {} more occurrences",
            group.members.len() - limit
        )?;
    }
    Ok(())
}

/// Render the model-derived artifact estimates without presenting them as a
/// guaranteed binary-size reduction.
fn render_artifact_savings(savings: &[ArtifactSavings], out: &mut impl Write) -> io::Result<()> {
    if savings.is_empty() {
        return Ok(());
    }
    writeln!(out, "    artifact refactoring estimates (not guaranteed):")?;
    for savings in savings {
        writeln!(
            out,
            "      analysis {}: {} estimated bytes from {} attributed duplicate bytes; mapping {}, clone {:.3}, model {}, savings {}",
            savings.artifact_analysis_id,
            savings.estimated_refactor_savings_bytes,
            savings.duplicated_bytes,
            savings.mapping_confidence,
            savings.clone_confidence,
            savings.model_confidence,
            savings.savings_confidence,
        )?;
        writeln!(
            out,
            "        source build variant: {}",
            savings.source_build_variant_fingerprint
        )?;
        writeln!(
            out,
            "        artifact build variant: {}",
            savings.artifact_build_variant_fingerprint
        )?;
        writeln!(
            out,
            "        model schema: {}",
            savings.model_schema_version
        )?;
        writeln!(out, "        assumptions: {}", savings.assumptions)?;
    }
    Ok(())
}
