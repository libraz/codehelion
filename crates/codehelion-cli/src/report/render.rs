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
    ArtifactSavings, BASELINE_COMPARE, BaselineStatus, Decoration, GONE_LISTED, GROUP_EXPANDED,
    GROUP_NEW, Group, Member, Report, SCOPE_FRAGMENT, Summary, TextOptions, UnusedRule, Write,
    budget_note, depth_truncation_files, duplicated_tokens, io, search_truncation_note,
    severed_note,
};

/// Ranking value at and above which a group is drawn as the report's own
/// answer to "what first".
const PRIORITY_HIGH: f64 = 0.70;

/// Ranking value below which a group recedes: still listed, still real, but
/// not what the reader was pointed at.
const PRIORITY_LOW: f64 = 0.50;

/// Widest location column the listing pads to.
///
/// A deeply nested path would otherwise push every unit name off the right of
/// the screen to keep a column that only one row needs.
const PATH_COLUMN_MAX: usize = 52;

/// Widest unit-name column the listing pads to, for the same reason.
const UNIT_COLUMN_MAX: usize = 32;

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

    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }

    fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
    }

    /// The composed ranking value, in the band it falls in.
    ///
    /// The listing is already in this order, so the colour is not saying
    /// anything the position does not. It is saying where the order stops
    /// being worth reading, which a column of numbers does not show.
    fn priority(&self, value: f64) -> String {
        let text = format!("{value:.2}");
        if value >= PRIORITY_HIGH {
            self.paint("1;31", &text)
        } else if value >= PRIORITY_LOW {
            self.paint("33", &text)
        } else {
            self.paint("2", &text)
        }
    }

    /// A location with its directory receding, so that the file and the line
    /// a reader is about to open stay the brightest thing on the line.
    fn location(&self, text: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        text.rfind('/').map_or_else(
            || text.to_string(),
            |cut| format!("{}{}", self.dim(&text[..=cut]), &text[cut + 1..]),
        )
    }
}

/// The column widths one listing shares.
///
/// Measured over the rows that will actually be written rather than over every
/// group, so that one very long path outside the limit does not indent the
/// listing that is read.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct GroupColumns {
    /// Width of the entry number; `0` writes no number at all, which is what
    /// a single group rendered on its own wants.
    number: usize,
    kind: usize,
    tokens: usize,
    path: usize,
    unit: usize,
}

impl GroupColumns {
    /// Measure a numbered listing.
    pub(super) fn measure(groups: &[&Group], opts: TextOptions) -> Self {
        let listed = groups.len().min(opts.group_limit());
        let mut columns = Self {
            number: decimal_width(listed),
            ..Self::default()
        };
        for group in groups.iter().take(opts.group_limit()) {
            columns.widen(group, opts);
        }
        columns.cap()
    }

    /// Measure one group written without a number.
    pub(super) fn single(group: &Group, opts: TextOptions) -> Self {
        let mut columns = Self::default();
        columns.widen(group, opts);
        columns.cap()
    }

    fn widen(&mut self, group: &Group, opts: TextOptions) {
        self.kind = self.kind.max(width(&group_kind(group, opts.decoration)));
        self.tokens = self.tokens.max(width(&thousands(duplicated_tokens(group))));
        for (_, member) in listed_members(group, opts) {
            self.path = self.path.max(width(&member_location(member)));
            self.unit = self.unit.max(member.unit.as_deref().map_or(0, width));
        }
    }

    const fn cap(mut self) -> Self {
        if self.path > PATH_COLUMN_MAX {
            self.path = PATH_COLUMN_MAX;
        }
        if self.unit > UNIT_COLUMN_MAX {
            self.unit = UNIT_COLUMN_MAX;
        }
        self
    }

    /// The entry number for one row, and the blank of the same width that
    /// every line under it is written against.
    fn gutter(&self, number: Option<usize>) -> (String, String) {
        if self.number == 0 {
            return (String::new(), String::new());
        }
        // One column wider than the number itself, so that the listing does
        // not start hard against the left edge of the terminal.
        let width = self.number + 2;
        let label = number.map_or_else(
            || " ".repeat(width),
            |value| format!("{:>width$}", format!("#{value}"), width = width),
        );
        (label, " ".repeat(width))
    }
}

/// Digits in the largest number a listing of `count` entries writes.
const fn decimal_width(count: usize) -> usize {
    let mut digits = 1;
    let mut remaining = count / 10;
    while remaining > 0 {
        digits += 1;
        remaining /= 10;
    }
    digits
}

/// The printed width of a string.
///
/// Character count rather than display width: paths and identifiers in the
/// languages this tool reads are ASCII, and the one column that could hold
/// anything else is the last on its line, where a mismeasured pad shows as
/// nothing.
fn width(text: &str) -> usize {
    text.chars().count()
}

/// Pad `text` to `width` columns, measuring what was written rather than what
/// the styling added.
fn pad(text: &str, painted: String, width: usize) -> String {
    let mut padded = painted;
    for _ in self::width(text)..width {
        padded.push(' ');
    }
    padded
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
        let separator = opts.decoration.separator();
        writeln!(
            out,
            "{}",
            palette.bold(&format!(
                "codehelion scan {separator} {} mode {separator} {}",
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
        writeln!(
            out,
            "{}",
            palette.bold(&headline.join(&format!(" {} ", opts.decoration.separator())))
        )?;
        render_supplemental_totals(summary, out)?;
        let run_label = self.run.run_id.map_or_else(
            || "run unrecorded".to_string(),
            |run_id| format!("run {run_id}"),
        );
        writeln!(
            out,
            "{} files, {} lines, {} tokens {separator}{}{}",
            thousands(summary.files.total),
            thousands(summary.lines),
            thousands(summary.tokens),
            run_label,
            run_status(self),
            separator = opts.decoration.separator(),
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
            if self.run.run_id.is_some() {
                writeln!(out, "snapshot: {}", self.run.database)?;
            } else {
                writeln!(out, "database: {} (run not recorded)", self.run.database)?;
            }
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
        self.render_legend(opts, palette, out)
    }

    /// What the listing's marks meant, and what to type next.
    ///
    /// Written once, under the counts, and only about what this report
    /// actually used: a legend for a mark nobody saw is a line every reader
    /// pays for and none of them needed.
    fn render_legend(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let listed: Vec<&Group> = self
            .groups
            .iter()
            .filter(|group| group.suppressed.is_none())
            .take(opts.group_limit())
            .collect();
        let Some(first) = listed.first() else {
            return Ok(());
        };
        let separator = format!(" {} ", opts.decoration.separator());
        let mut legend = Vec::new();
        let canonical = opts.decoration.canonical();
        if !canonical.is_empty() {
            legend.push(format!(
                "{canonical} the occurrence a group is measured against"
            ));
        }
        // Only when the listing used the word: "run" reads as a verb until
        // something says it is an extent.
        if listed.iter().any(|group| group.scope == SCOPE_FRAGMENT) {
            legend.push("\"run\" a repeated stretch of statements, not a whole unit".to_string());
        }
        // Every listed heading ends in this mark, so a listing existing at all
        // is what says the report used it. Explained because the mark reads as
        // a multiple of the code until something says it counts occurrences.
        legend.push(format!(
            "{}N the number of occurrences",
            opts.decoration.times(),
        ));
        if !legend.is_empty() {
            writeln!(out, "{}", palette.dim(&legend.join(&separator)))?;
        }
        let guidance = if self.run.run_id.is_some() {
            format!(
                "open one: codehelion explain {}{separator}list every group: --limit 0",
                opts.id(&first.fingerprint),
            )
        } else {
            "list every group: --limit 0".to_string()
        };
        writeln!(out, "{}", palette.dim(&guidance))
    }

    /// The parts of the group total that are a classification rather than a
    /// count: what is a run rather than a unit, what was folded away, and what
    /// was hidden by a default nobody typed.
    fn render_composition_detail(&self, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        let groups = &summary.groups;
        // Every line names the total it is a part of. These counts are read
        // against three different totals — two of them describe groups that
        // were listed, one describes runs that never reached the listing —
        // and a pronoun standing in for the total made them read as one.
        let listed = plural(groups.total, "listed group");
        if groups.fragment_scope > 0 {
            writeln!(
                out,
                "  of the {listed}, {} describe a repeated run inside units that are not clones \
                 of each other",
                thousands(groups.fragment_scope),
            )?;
        }
        let mut left_out = Vec::new();
        if groups.folded_runs > 0 {
            left_out.push(format!(
                "{} folded into groups that already cover them",
                thousands(groups.folded_runs),
            ));
        }
        if groups.subsumed_runs > 0 {
            left_out.push(format!(
                "{} covered by a longer run",
                thousands(groups.subsumed_runs),
            ));
        }
        if !left_out.is_empty() {
            writeln!(
                out,
                "  runs not among the {listed}: {}",
                left_out.join("; "),
            )?;
        }
        if groups.test_code > 0 {
            writeln!(
                out,
                "  of the {listed}, {} are duplication inside test code, which repeats itself by \
                 design; a group spanning a test and what it exercises is not counted here",
                thousands(groups.test_code),
            )?;
        }
        // Which mechanism hid a group is what says whether to argue with a
        // rule or with the detector, so the split is stated even when it is
        // all zeroes. Last, because it shares a total with none of the lines
        // above and reads as their heading when it stands first.
        writeln!(
            out,
            "  suppressed: {} noise, {} by rule",
            thousands(summary.suppressed.noise),
            thousands(summary.suppressed.by_rule),
        )
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
        self.render_notes_with_artifact_guidance(opts, out, true)
    }

    /// Render notes for one partition when an enclosing partitioned report
    /// will decide whether artifact guidance is needed for all partitions.
    pub(crate) fn render_notes_without_artifact_guidance(
        &self,
        opts: TextOptions,
        out: &mut impl Write,
    ) -> io::Result<()> {
        self.render_notes_with_artifact_guidance(opts, out, false)
    }

    fn render_notes_with_artifact_guidance(
        &self,
        opts: TextOptions,
        out: &mut impl Write,
        include_artifact_guidance: bool,
    ) -> io::Result<()> {
        if opts.quiet {
            return Ok(());
        }
        let summary = &self.summary;
        let mark = opts.decoration.warning();
        // Everything that says the report is not the whole answer comes
        // first, and says so in the word that means it. A reader who stops
        // after one line should have stopped after the line that changes what
        // the rest of the report means.
        //
        // A recovering parser reports no failure, so the share it could not
        // follow is the only thing separating "little duplication here" from
        // "most of this was never read".
        if let Some(unparsed) = &summary.unparsed
            && unparsed.files > 0
        {
            writeln!(
                out,
                "{mark}warning: the parser could not follow {:.2}% of the tokens, over {} of {} \
                 files",
                unparsed.share * 100.0,
                unparsed.files,
                summary.files.total,
            )?;
        }
        if summary.search_truncated {
            writeln!(
                out,
                "{mark}warning: {}",
                search_truncation_note(&summary.funnel),
            )?;
        }
        if summary.pair_budget_exhausted {
            writeln!(out, "{mark}warning: {}", budget_note(&summary.funnel))?;
        }
        if summary.split_components > 0 {
            writeln!(
                out,
                "{mark}warning: {} set(s) of related units were too large to compare as one and \
                 were cut; clones of each other may be reported as separate groups{}",
                summary.split_components,
                severed_note(&summary.funnel),
            )?;
        }
        if let Some(files) = depth_truncation_files(&summary.funnel) {
            writeln!(
                out,
                "{mark}warning: structural parsing reached its depth limit in {files} file(s); \
                 the deepest region of each was left out of analysis"
            )?;
        }
        // Then what qualifies the report without unsettling it: a rule that
        // matched nothing, a policy this mode could not apply.
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
        render_unmeasured_in_this_mode(summary, out)?;
        if include_artifact_guidance {
            render_artifact_guidance(self, out)?;
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
        let columns = GroupColumns::measure(&visible, opts);
        for (position, group) in visible.iter().take(limit).enumerate() {
            if position > 0 {
                writeln!(out)?;
            }
            render_group(group, Some(position + 1), opts, palette, &columns, out)?;
            if opts.show_siblings {
                self.render_siblings(group, opts, out)?;
            }
        }
        if visible.len() > limit {
            let left_out = remaining(visible.len(), limit);
            writeln!(out)?;
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
            let unmeasured = reported
                .iter()
                .filter(|group| group.identifier_jaccard.is_none())
                .count();
            let below_floor = reported
                .iter()
                .filter(|group| group.identifier_jaccard.is_some_and(|value| value < floor))
                .count();
            let unmeasured_clause = if unmeasured == 0 {
                String::new()
            } else {
                format!(" ({unmeasured} of them were not measured in this mode)")
            };
            writeln!(
                out,
                "{} group(s) are not listed: raw identifier agreement below {floor:.2}{}",
                reported.len() - visible.len(),
                unmeasured_clause,
            )?;
            debug_assert_eq!(reported.len() - visible.len(), below_floor + unmeasured);
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
                let columns = GroupColumns::measure(&suppressed, opts);
                for (position, group) in suppressed.iter().take(limit).enumerate() {
                    if position > 0 {
                        writeln!(out)?;
                    }
                    render_group(group, Some(position + 1), opts, palette, &columns, out)?;
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
                "  estimated Jaccard {:.2}: {}:{}{} {} {}:{}{}",
                near_miss.estimated_jaccard,
                near_miss.left.file,
                near_miss.left.start_line,
                near_miss
                    .left
                    .unit
                    .as_deref()
                    .map(|unit| format!(" ({unit})"))
                    .unwrap_or_default(),
                opts.decoration.between(),
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
            // How many units share the signature is the whole strength of this
            // channel: a signature held by a handful of units says something,
            // and one the whole layer shares says nothing. The number is shown
            // so the reader can tell those apart; it never moves the band.
            let evidence = match (sibling.basis.as_str(), sibling.signature_units) {
                ("signature", Some(units)) => format!(
                    "({:.2}) [same signature, {} units share it]",
                    sibling.similarity.composite,
                    thousands(units),
                ),
                ("signature", None) => {
                    format!("({:.2}) [same signature]", sibling.similarity.composite)
                }
                _ => format!("({:.2})", sibling.similarity.composite),
            };
            writeln!(
                out,
                "  sibling {} {} {}: {}:{}{}",
                sibling.clone_type,
                sibling.confidence_band,
                evidence,
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
fn run_status(report: &Report) -> String {
    let Some(run_id) = report.run.run_id else {
        return " (replay and baseline comparison unavailable)".to_string();
    };
    if report.run.reused {
        return format!(" (reused: tree unchanged; replay: codehelion report --run {run_id})");
    }
    if let Some(changes) = &report.summary.changes {
        let changed = changes
            .modified
            .saturating_add(changes.added)
            .saturating_add(changes.removed);
        return format!(
            " ({} file(s) changed; replay: codehelion report --run {})",
            thousands(changed),
            run_id
        );
    }
    // A report reconstructed by `report --run` has no invocation-level reuse
    // fact. Naming the replay is precise without inventing one.
    format!(" (replay: codehelion report --run {run_id})")
}

/// Totals for serialized supplemental evidence that the default body hides.
///
/// Counts come from the final vectors, while cap notes come from the recorded
/// funnel. A configured ceiling that dropped nothing is not mentioned.
fn render_supplemental_totals(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    let sibling_drops = funnel_drop_count(
        summary,
        &[
            "sibling_candidate_budget",
            "sibling_per_group_cap",
            "sibling_total_cap",
            "signature_sibling_candidate_budget",
            "signature_sibling_per_group_cap",
            "signature_sibling_total_cap",
        ],
    );
    let near_miss_drops = funnel_drop_count(summary, &["retention_cap"]);
    render_common_signatures(summary, out)?;
    if summary.siblings == 0 && summary.near_misses == 0 {
        let mut drops = Vec::new();
        if sibling_drops > 0 {
            drops.push(format!(
                "{} sibling candidate(s) dropped by search ceilings",
                thousands(sibling_drops)
            ));
        }
        if near_miss_drops > 0 {
            drops.push(format!(
                "{} near miss(es) dropped by the retention cap",
                thousands(near_miss_drops)
            ));
        }
        if !drops.is_empty() {
            writeln!(out, "supplemental: {}", drops.join(", "))?;
        }
        return Ok(());
    }
    let mut entries = Vec::new();
    if summary.siblings > 0 {
        let dropped = if sibling_drops > 0 {
            format!("; {} dropped by search ceilings", thousands(sibling_drops))
        } else {
            String::new()
        };
        entries.push(format!(
            "{} siblings (--show-siblings{})",
            thousands(summary.siblings),
            dropped
        ));
    }
    if summary.near_misses > 0 {
        let dropped = if near_miss_drops > 0 {
            format!(
                "; {} dropped by the retention cap",
                thousands(near_miss_drops)
            )
        } else {
            String::new()
        };
        entries.push(format!(
            "{} near misses (--show-near-misses{})",
            thousands(summary.near_misses),
            dropped
        ));
    }
    writeln!(out, "supplemental: {}", entries.join(", "))?;
    Ok(())
}

/// Signatures the sibling channel would not index because too much of the tree
/// shares them.
///
/// Printed unconditionally rather than behind a diagnostic switch, and before
/// the supplemental totals return early on an empty channel: the run where the
/// rarity gate silenced the channel outright is the run whose reader most
/// needs to know the channel does not fit this code.
fn render_common_signatures(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    if summary.common_signatures_skipped == 0 {
        return Ok(());
    }
    writeln!(
        out,
        "signature siblings: {} signatures skipped as too common (the most common covers {} units)",
        thousands(summary.common_signatures_skipped),
        thousands(summary.largest_skipped_signature_units),
    )
}

fn funnel_drop_count(summary: &Summary, causes: &[&str]) -> u64 {
    summary
        .funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| causes.contains(&drop.cause.as_str()))
        .map(|drop| drop.count)
        .fold(0, u64::saturating_add)
}

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
    write!(
        out,
        "  diagnostics: near-match band {}, at most {} near misses; sibling sweep {} comparisons, {} per group, {} total",
        guardrails.near_miss_delta,
        guardrails.near_miss_cap,
        guardrails.sibling_candidate_budget,
        guardrails.sibling_per_group_cap,
        guardrails.sibling_total_cap,
    )?;
    if summary
        .funnel
        .iter()
        .any(|stage| stage.stage == "signature sibling entries")
    {
        write!(
            out,
            "; signature sibling sweep {} candidates, {} per group, {} total",
            guardrails.signature_sibling_candidate_budget,
            guardrails.signature_sibling_per_group_cap,
            guardrails.signature_sibling_total_cap,
        )?;
    }
    writeln!(out)
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

/// Explain the measurements Fast intentionally leaves to Structural mode.
fn render_unmeasured_in_this_mode(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    if summary.unmeasured_in_this_mode.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "note: Fast duplicated-token totals may overlap because one source location can appear in multiple groups; this mode does not measure {}",
        summary.unmeasured_in_this_mode.join(", "),
    )
}

/// Give a source report a single path to artifact correlation when no group
/// has been hydrated with saved artifact evidence.
const ARTIFACT_GUIDANCE: &str = "note: no artifact savings are recorded; provide an artifact at <PATH> retaining symbols/debug info, or a matching companion via --debug-file <PATH>, then run artifact analyze <PATH> --source-run <id> --build-variant <manifest>";

fn artifact_guidance_needed<'a>(groups: impl Iterator<Item = &'a Group>) -> bool {
    let mut has_group = false;
    for group in groups {
        has_group = true;
        if !group.artifact_savings.is_empty() {
            return false;
        }
    }
    has_group
}

fn render_artifact_guidance(report: &Report, out: &mut impl Write) -> io::Result<()> {
    if report.run.run_id.is_none() {
        return Ok(());
    }
    if !artifact_guidance_needed(report.groups.iter()) {
        return Ok(());
    }
    writeln!(out, "{ARTIFACT_GUIDANCE}")
}

/// Render artifact guidance once for a partitioned report envelope.
pub(super) fn render_partition_artifact_guidance(
    reports: &[Report],
    out: &mut impl Write,
) -> io::Result<()> {
    if !artifact_guidance_needed(
        reports
            .iter()
            .filter(|report| report.run.run_id.is_some())
            .flat_map(|report| report.groups.iter()),
    ) {
        return Ok(());
    }
    writeln!(out, "{ARTIFACT_GUIDANCE}")
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
fn render_group_baseline(group: &Group, indent: &str, out: &mut impl Write) -> io::Result<()> {
    let Some(baseline) = &group.baseline else {
        return Ok(());
    };
    match baseline.state.as_str() {
        GROUP_NEW => match &baseline.derived_from {
            Some(derived) => writeln!(
                out,
                "{indent}  new since the baseline, standing where {} stood ({} occurrence(s) in \
                 the same place)",
                derived.group, derived.shared_sites,
            ),
            None => writeln!(out, "{indent}  new since the baseline"),
        },
        GROUP_EXPANDED => writeln!(
            out,
            "{indent}  expanded since the baseline: {} new occurrence(s)",
            baseline.added_instances.unwrap_or(0),
        ),
        _ => Ok(()),
    }
}

/// What a group is, as the heading's second column states it.
///
/// A fragment-scope group states its extent: without it "type-1, 40 tokens"
/// reads as a duplicated unit, which it is not.
fn group_kind(group: &Group, decoration: Decoration) -> String {
    let scope = if group.scope == SCOPE_FRAGMENT {
        format!("{} run", group.clone_type)
    } else {
        group.clone_type.clone()
    };
    format!(
        "{scope} {}{}",
        decoration.times(),
        group.priority.inputs.instances
    )
}

/// The bracketed qualifications on a group's heading: why it is ranked where
/// it is, and where it stands against the baseline.
fn group_markers(group: &Group, palette: &Palette) -> String {
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
    format!("{}{overlap}{marker}", baseline_marker(group, palette))
}

/// The occurrences one group writes, canonical first.
///
/// The canonical occurrence leads because it is the one the group is measured
/// against and the one a reader opens first; every other order makes that a
/// fact you have to look for.
fn listed_members(group: &Group, opts: TextOptions) -> Vec<(bool, &Member)> {
    let anchor = group
        .members
        .iter()
        .position(|member| member.canonical)
        .unwrap_or(0);
    let mut ordered: Vec<(bool, &Member)> = group
        .members
        .iter()
        .enumerate()
        .map(|(index, member)| (index == anchor, member))
        .collect();
    ordered.sort_by_key(|(canonical, _)| !canonical);
    ordered.truncate(opts.member_limit());
    ordered
}

/// The mark on the canonical occurrence, and the blank that keeps every other
/// occurrence in the same column.
fn canonical_mark(canonical: bool, decoration: Decoration) -> String {
    let glyph = decoration.canonical();
    if glyph.is_empty() {
        return String::new();
    }
    if canonical {
        format!("{glyph} ")
    } else {
        " ".repeat(width(glyph) + 1)
    }
}

/// Render one group.
///
/// A heading of ranking and kind, then the occurrences under it as a tree. The
/// ranked value leads the line because it is what the listing is in order on,
/// and a sort key buried on the right is one a reader cannot follow down the
/// page. The numbers behind that value follow only when they were asked for.
pub(super) fn render_group(
    group: &Group,
    number: Option<usize>,
    opts: TextOptions,
    palette: &Palette,
    columns: &GroupColumns,
    out: &mut impl Write,
) -> io::Result<()> {
    let (gutter, indent) = columns.gutter(number);
    let kind = group_kind(group, opts.decoration);
    let tokens = thousands(duplicated_tokens(group));
    writeln!(
        out,
        "{gutter}  {}  {kind:kind_width$}  {tokens:>tokens_width$} tokens  {}{}",
        palette.priority(group.priority.value),
        palette.cyan(opts.id(&group.fingerprint)),
        group_markers(group, palette),
        kind_width = columns.kind,
        tokens_width = columns.tokens,
    )?;
    if opts.detailed() {
        render_group_detail(group, &indent, out)?;
    }
    render_group_members(group, opts, palette, columns, &indent, out)
}

/// The measures behind one group's placement, for a reader who wants to
/// disagree with it.
fn render_group_detail(group: &Group, indent: &str, out: &mut impl Write) -> io::Result<()> {
    render_group_baseline(group, indent, out)?;
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
    writeln!(out, "{indent}  {spread}, {identifiers}{extent}")?;
    // The composed number is never shown on its own: the three measures that
    // made it say why the finding is where it is, and disagreeing with the
    // placement means disagreeing with one of them.
    writeln!(
        out,
        "{indent}  confidence {:.2}, maintenance risk {:.2}, refactoring difficulty {:.2} \
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
        writeln!(out, "{indent}  {}", similarity.line())?;
    }
    writeln!(
        out,
        "{indent}  content entropy: {:.2} bits",
        group.entropy_bits
    )?;
    if let Some(body) = group.body_materiality {
        writeln!(
            out,
            "{indent}  body evidence: loop {}, recognised allocation {}, at least {} call site(s)",
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
/// Every occurrence is listed, the canonical one included and marked: the
/// heading no longer names a location, so a list that left one out would be
/// describing a group nobody can see all of.
fn render_group_members(
    group: &Group,
    opts: TextOptions,
    palette: &Palette,
    columns: &GroupColumns,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
    let listed = listed_members(group, opts);
    let omitted = remaining(group.members.len(), listed.len());
    if listed.is_empty() {
        writeln!(
            out,
            "{indent}  {}(no recorded occurrence)",
            opts.decoration.last_branch(),
        )?;
        return Ok(());
    }
    for (position, (canonical, member)) in listed.iter().enumerate() {
        // The last branch closes the group, so it belongs to whatever line
        // ends it — the omitted-occurrence count when there is one.
        let last = omitted == 0 && position + 1 == listed.len();
        let branch = if last {
            opts.decoration.last_branch()
        } else {
            opts.decoration.branch()
        };
        let location = member_location(member);
        let trailing = member_trailing(member, opts, palette, columns);
        let line = format!(
            "{indent}  {branch}{}{}{trailing}",
            canonical_mark(*canonical, opts.decoration),
            pad(&location, palette.location(&location), columns.path),
        );
        writeln!(out, "{}", line.trim_end())?;
    }
    if omitted > 0 {
        writeln!(
            out,
            "{indent}  {}... and {omitted} more {}",
            opts.decoration.last_branch(),
            noun_form(omitted, "occurrence"),
        )?;
    }
    Ok(())
}

/// What follows an occurrence's location: the unit it sits in, and the
/// identifier that opens it when identifiers were asked for.
fn member_trailing(
    member: &Member,
    opts: TextOptions,
    palette: &Palette,
    columns: &GroupColumns,
) -> String {
    let unit = member.unit.as_deref().unwrap_or_default();
    if !opts.detailed() {
        if unit.is_empty() {
            return String::new();
        }
        return format!("  {}", palette.dim(unit));
    }
    format!(
        "  {}  {}",
        pad(unit, palette.dim(unit), columns.unit),
        palette.dim(&format!("[finding {}]", opts.id(&member.finding_id))),
    )
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
