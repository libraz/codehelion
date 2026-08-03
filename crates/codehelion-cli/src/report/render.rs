//! Human-readable scan report rendering.
//!
//! The text view has three depths, chosen by `--verbose`. The default says
//! what was found and where; `-v` adds the numbers each group was ranked on
//! and what the scan read; `-vv` adds what the run itself did — the candidate
//! pipeline, the ceilings that applied, and full identifiers.
//!
//! Notes about an incomplete or ceiling-bound run are not part of any depth.
//! [`Report::render_notes`] writes them separately so that the report on
//! standard output stays something a pipe can read.

use super::{
    ArtifactSavings, BASELINE_COMPARE, BaselineStatus, GONE_LISTED, GROUP_EXPANDED, GROUP_NEW,
    Group, Member, Report, SCOPE_FRAGMENT, Summary, TextOptions, UnusedRule, Write, budget_note,
    depth_truncation_files, duplicated_tokens, io, search_truncation_note, severed_note,
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

/// A count with thousands separators, because six-digit token counts are read
/// as often as they are compared.
fn thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

/// How many of `total` a limit left out, as the count a note prints.
fn remaining(total: usize, limit: usize) -> u64 {
    u64::try_from(total.saturating_sub(limit)).unwrap_or(u64::MAX)
}

/// `1 group` or `12 groups`, so a summary line does not read as a template.
fn plural(count: u64, noun: &str) -> String {
    format!("{} {}", thousands(count), noun_form(count, noun))
}

/// The singular or plural noun for `count`.
fn noun_form(count: u64, noun: &str) -> String {
    if count == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

/// Where one occurrence sits, in the form an editor and a grep both accept.
fn member_location(member: &Member) -> String {
    format!("{}:{}-{}", member.file, member.start_line, member.end_line)
}

/// The enclosing unit, parenthesised, or nothing when parsing recovered none.
fn member_unit(member: &Member) -> String {
    member
        .unit
        .as_deref()
        .map_or_else(String::new, |name| format!(" ({name})"))
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
        if !opts.quiet {
            self.render_heading(opts, &palette, out)?;
            writeln!(out)?;
        }
        self.render_groups(opts, &palette, out)?;
        if opts.show_near_misses {
            self.render_near_misses(opts, &palette, out)?;
        }
        if !opts.quiet {
            self.render_totals(opts, &palette, out)?;
        }
        Ok(())
    }

    /// Write what the reader has to know before reading a single number:
    /// which tree, in which mode, and — when asked — under what settings.
    fn render_heading(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        writeln!(
            out,
            "{}",
            palette.bold(&format!(
                "codehelion scan · {} mode · {}",
                self.run.mode, self.run.root
            ))
        )?;
        if opts.detailed() {
            self.render_configuration(out)?;
            self.render_inputs(opts, out)?;
        }
        if opts.diagnostic() {
            self.render_funnel(palette, out)?;
        }
        Ok(())
    }

    /// The counts that close the report: what was found, over how much, and
    /// how to open it again.
    fn render_totals(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(out)?;
        let composition = group_composition(summary);
        let counted = if composition.is_empty() {
            plural(summary.groups.total, "group")
        } else {
            format!("{} ({composition})", plural(summary.groups.total, "group"))
        };
        let suppressed = summary.suppressed.noise + summary.suppressed.by_rule;
        let mut headline = vec![counted];
        if suppressed > 0 {
            headline.push(format!("{} suppressed", thousands(suppressed)));
        }
        headline.push(format!("sorted by {}", opts.sort.name()));
        writeln!(out, "{}", palette.bold(&headline.join(" · ")))?;
        writeln!(
            out,
            "{} files, {} lines, {} tokens · run {} (replay: codehelion report --run {})",
            thousands(summary.files.total),
            thousands(summary.lines),
            thousands(summary.tokens),
            self.run.run_id,
            self.run.run_id,
        )?;
        // Hidden without anybody asking, so the report says it happened and
        // says how to undo it — at every depth, because a default nobody can
        // see is a default nobody can disagree with.
        if summary.suppressed.vendored > 0 {
            writeln!(
                out,
                "{} of them are duplication inside vendored trees, which this project does not \
                 write; --include-vendored reports them",
                summary.suppressed.vendored,
            )?;
        }
        if opts.detailed() {
            self.render_composition_detail(out)?;
            writeln!(out, "snapshot: {}", self.run.database)?;
        }
        if let Some(baseline) = &summary.baseline {
            writeln!(
                out,
                "baseline {}: {} of {} matched, {} gone, {} new, {} expanded",
                baseline.file,
                baseline.matched,
                baseline.entries,
                baseline.stale,
                baseline.appeared,
                baseline.expanded,
            )?;
        }
        Ok(())
    }

    /// The parts of the group total that are a classification rather than a
    /// count: what is a run rather than a unit, what was folded away, and what
    /// was hidden by a default nobody typed.
    fn render_composition_detail(&self, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        // Which mechanism hid a group is what says whether to argue with a
        // rule or with the detector, so the split is stated even when it is
        // all zeroes.
        writeln!(
            out,
            "  suppressed: {} noise, {} by rule",
            summary.suppressed.noise, summary.suppressed.by_rule,
        )?;
        let runs = &summary.groups;
        if runs.fragment_scope > 0 || runs.folded_runs > 0 || runs.subsumed_runs > 0 {
            writeln!(
                out,
                "  {} of them are runs duplicated inside units that are not clones of each \
                 other; {} more were folded into the groups that already cover them and {} \
                 into longer runs",
                runs.fragment_scope, runs.folded_runs, runs.subsumed_runs,
            )?;
        }
        if summary.groups.test_code > 0 {
            writeln!(
                out,
                "  {} of them are duplication inside test code, which repeats itself by \
                 design; a group spanning a test and what it exercises is not counted here",
                summary.groups.test_code,
            )?;
        }
        Ok(())
    }

    /// Write what qualifies the whole report rather than any part of it: an
    /// incomplete read, a ceiling that fired, a rule that matched nothing.
    ///
    /// Separate from [`Self::render_text`] because these belong on the error
    /// stream: they are about the run, and a reader piping the report into
    /// something else should still see them.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_notes(&self, opts: TextOptions, out: &mut impl Write) -> io::Result<()> {
        if opts.quiet {
            return Ok(());
        }
        let summary = &self.summary;
        // A recovering parser reports no failure, so the share it could not
        // follow is the only thing separating "little duplication here" from
        // "most of this was never read".
        if let Some(unparsed) = &summary.unparsed
            && unparsed.files > 0
        {
            writeln!(
                out,
                "warning: the parser could not follow {:.2}% of the tokens, over {} of {} files",
                unparsed.share * 100.0,
                unparsed.files,
                summary.files.total,
            )?;
        }
        if !summary.unused_suppressions.is_empty() {
            let names: Vec<String> = summary
                .unused_suppressions
                .iter()
                .map(UnusedRule::label)
                .collect();
            writeln!(
                out,
                "note: {} suppression rule(s) matched nothing: {}",
                summary.unused_suppressions.len(),
                names.join(", "),
            )?;
        }
        render_unapplied_suppression_policies(summary, out)?;
        if summary.split_components > 0 {
            writeln!(
                out,
                "note: {} set(s) of related units were too large to compare as one and were \
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
                "note: structural parsing reached its depth limit in {files} file(s); the deepest region of each was left out of analysis"
            )?;
        }
        Ok(())
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
    fn render_inputs(&self, opts: TextOptions, out: &mut impl Write) -> io::Result<()> {
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
        // Only the causes that excluded something: a row of zeroes is a row
        // the eye has to check before it can dismiss it.
        let excluded = excluded_causes(summary);
        if excluded.is_empty() {
            writeln!(out, "  excluded: none")?;
        } else {
            writeln!(
                out,
                "  excluded: {} ({} total)",
                excluded.join(", "),
                summary.excluded.total(),
            )?;
        }
        writeln!(
            out,
            "  lines: {}; tokens: {}; lexer diagnostics: {}",
            thousands(summary.lines),
            thousands(summary.tokens),
            summary.lexer_diagnostics,
        )?;
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
            render_helper_diagnostics(out, &compiler.diagnostics)?;
            for refusal in &compiler.execution_refusals {
                writeln!(out, "    {} file(s): {}", refusal.files, refusal.message)?;
            }
        }
        if opts.diagnostic() {
            render_guardrails(summary, out)?;
        }
        if let Some(baseline) = &summary.baseline {
            render_baseline_detail(baseline, out)?;
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
        let limit = opts.group_limit();
        for group in visible.iter().take(limit) {
            render_group(group, opts, palette, out)?;
            if opts.show_siblings {
                self.render_siblings(group, opts, out)?;
            }
        }
        if visible.len() > limit {
            let left_out = remaining(visible.len(), limit);
            writeln!(
                out,
                "... and {left_out} more {} (--limit 0 lists every one)",
                noun_form(left_out, "group"),
            )?;
        }
        // A floor that quietly swallowed the unmeasured, or the listing that
        // came out of it, would read as "there is nothing else". Said after
        // the listing because it qualifies what was just read.
        if let Some(floor) = opts.min_identifier_jaccard
            && reported.len() > visible.len()
        {
            writeln!(
                out,
                "{} group(s) are not listed: raw identifier agreement below {floor:.2}, or not \
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
                for group in suppressed.iter().take(limit) {
                    render_group(group, opts, palette, out)?;
                    if opts.show_siblings {
                        self.render_siblings(group, opts, out)?;
                    }
                }
                if suppressed.len() > limit {
                    let left_out = remaining(suppressed.len(), limit);
                    writeln!(
                        out,
                        "... and {left_out} more suppressed {}",
                        noun_form(left_out, "group"),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Render run-scoped diagnostics only when the text caller requested
    /// them. They are not grouped or ranked because the primary detector
    /// deliberately rejected them before verification.
    fn render_near_misses(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let visible: Vec<_> = self
            .near_misses
            .iter()
            .filter(|near_miss| opts.show_suppressed || near_miss.suppressed.is_none())
            .collect();
        if visible.is_empty() {
            return Ok(());
        }
        let limit = opts.group_limit();
        writeln!(out)?;
        writeln!(out, "{}", palette.bold("near-match near misses:"))?;
        for near_miss in visible.iter().take(limit) {
            writeln!(
                out,
                "  estimated Jaccard {:.2}: {}:{}{} ↔ {}:{}{}",
                near_miss.estimated_jaccard,
                near_miss.left.file,
                near_miss.left.start_line,
                near_miss
                    .left
                    .unit
                    .as_deref()
                    .map(|unit| format!(" ({unit})"))
                    .unwrap_or_default(),
                near_miss.right.file,
                near_miss.right.start_line,
                near_miss
                    .right
                    .unit
                    .as_deref()
                    .map(|unit| format!(" ({unit})"))
                    .unwrap_or_default(),
            )?;
        }
        if visible.len() > limit {
            writeln!(out, "  ... and {} more near misses", visible.len() - limit)?;
        }
        Ok(())
    }

    /// Render local incomplete mirrors only when the text caller requested
    /// them. JSON and SARIF retain the data unconditionally.
    fn render_siblings(
        &self,
        group: &Group,
        opts: TextOptions,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let Some(siblings) = self
            .siblings
            .iter()
            .find(|siblings| siblings.group_fingerprint == group.fingerprint)
        else {
            return Ok(());
        };
        for sibling in siblings
            .siblings
            .iter()
            .filter(|sibling| opts.show_suppressed || sibling.suppressed.is_none())
        {
            let member = &sibling.member;
            writeln!(
                out,
                "  sibling {} {} ({:.2}): {}:{}{}",
                sibling.clone_type,
                sibling.confidence_band,
                sibling.similarity.composite,
                member.file,
                member.start_line,
                member_unit(member),
            )?;
        }
        Ok(())
    }
}

/// The group total broken down by clone type, leaving out the types this mode
/// cannot report.
fn group_composition(summary: &Summary) -> String {
    let groups = &summary.groups;
    let counted = [
        ("type-1", groups.type_1),
        ("type-2", groups.type_2),
        ("type-3", groups.type_3),
        ("restricted-semantic", groups.restricted_semantic),
    ];
    counted
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{label} {count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The exclusion causes that excluded something, named with their counts.
fn excluded_causes(summary: &Summary) -> Vec<String> {
    let excluded = &summary.excluded;
    let counted = [
        ("generated", excluded.generated),
        ("by glob", excluded.by_glob),
        ("too large", excluded.too_large),
        ("binary", excluded.binary),
        ("unreadable", excluded.unreadable),
        ("language-disabled", excluded.language_excluded),
        ("symlinks", excluded.symlinks),
        ("walk errors", excluded.walk_errors),
        ("timed out", excluded.timed_out),
    ];
    counted
        .iter()
        .filter(|(_, count)| *count > 0)
        .map(|(label, count)| format!("{count} {label}"))
        .collect()
}

/// The ceilings this run analysed under, and the ones its diagnostics used.
fn render_guardrails(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    let Some(guardrails) = &summary.guardrails else {
        return Ok(());
    };
    writeln!(
        out,
        "  {} profile: files over {} bytes skipped, parse work capped at min(file ceiling, {} ms × {} bytes), {} ms helper deadline, posting lists up to {}, {} candidate pairs per pass, {} verification pairs, {} cells per alignment, {} units per group",
        guardrails.profile,
        guardrails.max_file_bytes,
        guardrails.parse_timeout_ms,
        crate::scan::runtime::PARSE_BYTES_PER_MILLISECOND,
        guardrails.helper_timeout_ms,
        guardrails.posting_cap,
        guardrails.pair_budget,
        guardrails.verification_budget,
        guardrails.max_alignment_cells,
        guardrails.max_component,
    )?;
    writeln!(
        out,
        "  diagnostics: near-match band {}, at most {} near misses; sibling sweep {} comparisons, {} per group, {} total",
        guardrails.near_miss_delta,
        guardrails.near_miss_cap,
        guardrails.sibling_candidate_budget,
        guardrails.sibling_per_group_cap,
        guardrails.sibling_total_cap,
    )
}

/// What the baseline covered, said as counts and then as a before and an
/// after.
fn render_baseline_detail(baseline: &BaselineStatus, out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "  baseline {}: {} of {} entries matched, {} no longer found",
        baseline.file, baseline.matched, baseline.entries, baseline.stale,
    )?;
    // The same counts said as a before and an after, which is the question
    // somebody working duplication down is asking.
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
    render_gone(baseline, out)
}

fn render_helper_diagnostics(
    out: &mut impl Write,
    diagnostics: &std::collections::BTreeMap<String, u64>,
) -> io::Result<()> {
    for (diagnostic, count) in diagnostics {
        writeln!(out, "    {count} helper diagnostic: {diagnostic}")?;
    }
    Ok(())
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
            "note: Fast mode did not apply suppression policies that require structural classifications: {}; run with --mode structural or --mode semantic to apply them",
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

/// Where a group stands relative to the baseline, short enough for the
/// heading line.
///
/// Only new and expanded groups get a marker. "Continuing" is the
/// unremarkable case and marking every one of them would bury the changes
/// that matter.
fn baseline_marker(group: &Group, palette: &Palette) -> String {
    let Some(baseline) = &group.baseline else {
        return String::new();
    };
    match baseline.state.as_str() {
        GROUP_NEW => format!(" {}", palette.yellow("[new]")),
        GROUP_EXPANDED => format!(
            " {}",
            palette.yellow(&format!(
                "[expanded +{}]",
                baseline.added_instances.unwrap_or(0)
            ))
        ),
        _ => String::new(),
    }
}

/// Say where a group stands relative to the baseline the run was given, in
/// the sentence the detailed view has room for.
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

/// Render one group.
///
/// The heading is one line in the shape every other command-line tool puts a
/// finding in: where it is, what it is, and the identifier that opens it. The
/// numbers it was ranked on follow only when they were asked for.
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
    let kind = if group.scope == SCOPE_FRAGMENT {
        format!("{} run", group.clone_type)
    } else {
        group.clone_type.clone()
    };
    // The heading names the occurrence a reader opens first: the canonical
    // one, or the first recorded when no member claims it.
    let canonical = group.members.iter().position(|member| member.canonical);
    let anchor = group.members.get(canonical.unwrap_or(0));
    let location = anchor.map_or_else(
        || "(no recorded occurrence)".to_string(),
        |member| format!("{}{}", member_location(member), member_unit(member)),
    );
    let priority = &group.priority;
    writeln!(
        out,
        "{location}  {kind} ×{}  {} tokens  priority {:.2}  {}{}{overlap}{marker}",
        priority.inputs.instances,
        thousands(duplicated_tokens(group)),
        priority.value,
        palette.cyan(opts.id(&group.fingerprint)),
        baseline_marker(group, palette),
    )?;
    if opts.detailed() {
        render_group_detail(group, out)?;
    }
    render_group_members(group, opts, canonical, out)
}

/// The measures behind one group's placement, for a reader who wants to
/// disagree with it.
fn render_group_detail(group: &Group, out: &mut impl Write) -> io::Result<()> {
    render_group_baseline(group, out)?;
    let priority = &group.priority;
    let spread = match (priority.inputs.files, priority.inputs.directories) {
        (0 | 1, _) => "within one file",
        (_, 0 | 1) => "within one directory",
        _ => "across directories",
    };
    let identifiers = group.identifier_jaccard.map_or_else(
        || "identifiers n/a".to_string(),
        |value| format!("identifiers {value:.2}"),
    );
    let extent = match (group.scope.as_str(), group.statements) {
        (SCOPE_FRAGMENT, Some(statements)) => format!(", run of {statements} statements"),
        _ => String::new(),
    };
    writeln!(out, "    {spread}, {identifiers}{extent}")?;
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
    render_artifact_savings(&group.artifact_savings, out)
}

/// The occurrences under one group's heading.
///
/// The default view leaves out the occurrence the heading already named; the
/// detailed view repeats it, marked, because a complete list is the point of
/// asking for detail.
fn render_group_members(
    group: &Group,
    opts: TextOptions,
    canonical: Option<usize>,
    out: &mut impl Write,
) -> io::Result<()> {
    let listed: Vec<(usize, &Member)> = group
        .members
        .iter()
        .enumerate()
        .filter(|(index, _)| opts.detailed() || Some(*index) != canonical)
        .collect();
    let limit = opts.member_limit();
    for (index, member) in listed.iter().take(limit) {
        let detail = if opts.detailed() {
            format!(
                "{} [finding {}]",
                if Some(*index) == canonical {
                    " [canonical]"
                } else {
                    ""
                },
                opts.id(&member.finding_id),
            )
        } else {
            String::new()
        };
        writeln!(
            out,
            "  {}{}{detail}",
            member_location(member),
            member_unit(member),
        )?;
    }
    if listed.len() > limit {
        let left_out = remaining(listed.len(), limit);
        writeln!(
            out,
            "  ... and {left_out} more {}",
            noun_form(left_out, "occurrence"),
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
