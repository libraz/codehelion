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
    ArtifactSavings, BASELINE_COMPARE, BaselineStatus, Decoration, FunnelCause, GONE_LISTED,
    GROUP_EXPANDED, GROUP_NEW, Group, IDENTITY_ADOPTED, IDENTITY_RETAINED, Member, Report,
    ReportedSeam, SCOPE_FRAGMENT, Summary, TextOptions, UnusedRule, Write, budget_note,
    canonical_position, depth_truncation_files, duplicated_tokens, io, nesting_truncation_bodies,
    search_truncation_note, severed_note,
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

/// How many leading characters of a commit id the seam section prints.
///
/// The same abbreviation `codehelion seam` writes, so a commit named in one
/// place and in the other is recognisably the same commit.
const ABBREVIATED_COMMIT: usize = 8;

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
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
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
            self.render_seams(&palette, out)?;
            self.render_totals(opts, &palette, out)?;
        }
        Ok(())
    }

    /// What the seams written into the ledger have cost, and what moved since
    /// the generation before this one.
    ///
    /// Read from a recorded `codehelion seam` run, so a report that has none
    /// says nothing rather than a row of zeroes: a ledger nobody has evaluated
    /// is not a ledger whose seams cost nothing.
    fn render_seams(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        let Some(seam) = &self.seam else {
            return Ok(());
        };
        if seam.seams.is_empty() {
            return Ok(());
        }
        writeln!(out)?;
        let label = "seams: ";
        let indent = " ".repeat(label.len());
        for (position, entry) in seam.seams.iter().enumerate() {
            let prefix = if position == 0 { label } else { &indent };
            writeln!(
                out,
                "{prefix}{} {}",
                palette.bold(&entry.id),
                seam_clauses(entry).join(", "),
            )?;
        }
        let Some(since) = seam.since_seam_run_id else {
            return Ok(());
        };
        let moved: Vec<String> = seam
            .seams
            .iter()
            .filter_map(|entry| {
                let clauses = seam_delta_clauses(entry);
                (!clauses.is_empty()).then(|| format!("{} {}", entry.id, clauses.join(", ")))
            })
            .collect();
        if moved.is_empty() {
            return Ok(());
        }
        writeln!(
            out,
            "{}",
            palette.dim(&format!("since seam run {since}: {}", moved.join("; "))),
        )
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
        render_top_churn(summary, out)?;
        let run_label = self.run.run_id.map_or_else(
            || "run unrecorded".to_string(),
            |run_id| format!("run {run_id}"),
        );
        writeln!(
            out,
            "{} files, {} lines, {} tokens {separator} {}{}",
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

    /// The groups this report has to say something about: everything no rule
    /// hid, before the view narrows it.
    fn reported(&self) -> Vec<&Group> {
        self.groups
            .iter()
            .filter(|group| group.suppressed.is_none())
            .collect()
    }

    /// The groups the listing shows, in listing order.
    ///
    /// One rule for the listing and for the legend that says what to type
    /// next: a legend naming a group the same view filtered out would send a
    /// reader after something this report does not contain.
    fn visible(&self, opts: TextOptions) -> Vec<&Group> {
        self.reported()
            .into_iter()
            .filter(|group| {
                opts.min_identifier_jaccard.is_none_or(|floor| {
                    group
                        .identifier_jaccard
                        .is_some_and(|measured| measured >= floor)
                })
            })
            .collect()
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
            .visible(opts)
            .into_iter()
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
                "open one: codehelion explain{} {}{separator}list every group: --limit 0",
                database_flag(self),
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
        // against three different totals — two of them describe groups this
        // report holds, one describes runs that never reached it — and a
        // pronoun standing in for the total made them read as one.
        //
        // "reported", not "listed": these count every group the report holds,
        // while `--limit` decides how many the listing below enumerates. The
        // legend applies that limit and calls its own population listed, so
        // one word for both would name two different sets in one view.
        let reported = plural(groups.total, "reported group");
        if groups.fragment_scope > 0 {
            writeln!(
                out,
                "  of the {reported}, {} describe a repeated run inside units that are not clones \
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
                "{} covered by a longer finding",
                thousands(groups.subsumed_runs),
            ));
        }
        if !left_out.is_empty() {
            // "findings", not "runs": a duplicated function nested inside
            // another duplicated function leaves the same way a run covered by
            // a longer run does, and naming only runs would leave a reader
            // counting the difference against the wrong total.
            writeln!(
                out,
                "  findings not among the {reported}: {}",
                left_out.join("; "),
            )?;
        }
        if groups.test_code > 0 {
            writeln!(
                out,
                "  of the {reported}, {} are duplication inside test code, which repeats itself by \
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
        // The same fact for the mode that cuts fragments instead of parsing:
        // the files were read whole, and the blocks below the extraction depth
        // were not cut into anything a renamed-copy pass could match.
        if let Some(bodies) = nesting_truncation_bodies(&summary.funnel) {
            writeln!(
                out,
                "{mark}warning: fragment extraction reached its nesting limit in {bodies} \
                 block(s); duplication confined to those bodies is not reported"
            )?;
        }
        // Then what qualifies the report without unsettling it: a rule that
        // matched nothing, a policy this mode could not apply.
        let (covering, matched_nothing): (Vec<&UnusedRule>, Vec<&UnusedRule>) = summary
            .unused_suppressions
            .iter()
            .partition(|rule| rule.matched > 1);
        if !matched_nothing.is_empty() {
            let names: Vec<String> = matched_nothing.iter().map(|rule| rule.label()).collect();
            writeln!(
                out,
                "note: {} suppression rule(s) matched nothing: {}",
                matched_nothing.len(),
                names.join(", "),
            )?;
        }
        // A clone id names one duplication, so a prefix that has come to cover
        // several is hiding groups nobody judged. Named with the count, which
        // is what tells the reader the id no longer says what it said.
        if !covering.is_empty() {
            let names: Vec<String> = covering
                .iter()
                .map(|rule| format!("{} ({} groups)", rule.label(), rule.matched))
                .collect();
            writeln!(
                out,
                "note: {} suppression rule(s) hide more than the one group they name: {}",
                covering.len(),
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
            // Both gaps are broken down, and each breakdown says which gap it
            // belongs to: a file nothing describes how to compile and a helper
            // that died are answered by different work, and unlabelled reason
            // lines under one compiler line cannot be told apart.
            if !compiler.not_asked_reasons.is_empty() {
                writeln!(
                    out,
                    "    not asked: {}",
                    by_reason(&compiler.not_asked_reasons)
                )?;
            }
            if !compiler.unavailable.is_empty() {
                writeln!(out, "    unanswered: {}", by_reason(&compiler.unavailable))?;
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
        self.render_timings(out)?;
        Ok(())
    }

    /// How long the run spent analysing and how long it spent recording.
    ///
    /// Written here rather than on the default line because it is not part of
    /// what the scan found. It is here at all because the two halves can be
    /// wildly different sizes, and which of them dominates is what decides
    /// whether reuse is worth arranging.
    fn render_timings(&self, out: &mut impl Write) -> io::Result<()> {
        let Some(timings) = self.run.timings else {
            return Ok(());
        };
        let recorded = match (timings.recording, self.run.reused) {
            (Some(elapsed), _) => format!("recorded in {}", seconds(elapsed)),
            // Nothing was written because there was nothing new to write. The
            // saving is the point of saying so.
            (None, true) => "recorded: reused, nothing written".to_owned(),
            (None, false) => "not recorded".to_owned(),
        };
        writeln!(out, "  analysis {}, {recorded}", seconds(timings.analysis))
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
        let reported = self.reported();
        let visible = self.visible(opts);
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
            // Only the reasons that applied are named. A mode measuring no
            // identifier agreement at all leaves nothing below the floor, and
            // a mode measuring all of it leaves nothing unmeasured; naming
            // both regardless tells the reader the count may split two ways
            // when it cannot, which is exactly the split they wanted read.
            let reason = if below_floor == 0 {
                "raw identifier agreement is not measured in this mode".to_string()
            } else if unmeasured == 0 {
                format!("raw identifier agreement below {floor:.2}")
            } else {
                format!(
                    "raw identifier agreement below {floor:.2} ({unmeasured} of them were not \
                     measured in this mode)"
                )
            };
            writeln!(
                out,
                "{} group(s) are not listed: {reason}",
                reported.len() - visible.len(),
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
            let evidence = signature_note(&sibling.basis, sibling.signature_units).map_or_else(
                || format!("({:.2})", sibling.similarity.composite),
                |note| format!("({:.2}) {note}", sibling.similarity.composite),
            );
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

/// What a signature-channel sibling's evidence is worth, in the words every
/// text view says it in.
///
/// How many units share the signature is the whole strength of this channel: a
/// signature held by a handful of units says something, and one the whole layer
/// shares says nothing. The number is shown so the reader can tell those apart;
/// it never moves the confidence band. `None` is a sibling from the similarity
/// channel, whose evidence is the score alone.
pub(super) fn signature_note(basis: &str, signature_units: Option<u64>) -> Option<String> {
    match (basis, signature_units) {
        ("signature", Some(units)) => Some(format!(
            "[same signature, {} units share it]",
            thousands(units)
        )),
        ("signature", None) => Some("[same signature]".to_owned()),
        _ => None,
    }
}

/// The group total broken down by clone type, leaving out the types this mode
/// cannot report.
fn run_status(report: &Report) -> String {
    let Some(run_id) = report.run.run_id else {
        return " (replay and baseline comparison unavailable)".to_string();
    };
    let database = database_flag(report);
    if report.run.reused {
        return format!(
            " (reused: tree unchanged; replay: codehelion report{database} --run {run_id})"
        );
    }
    if let Some(changes) = &report.summary.changes {
        let changed = changes
            .modified
            .saturating_add(changes.added)
            .saturating_add(changes.removed);
        return format!(
            " ({} file(s) changed; replay: codehelion report{database} --run {run_id})",
            thousands(changed),
        );
    }
    // A report reconstructed by `report --run` has no invocation-level reuse
    // fact. Naming the replay is precise without inventing one.
    format!(" (replay: codehelion report{database} --run {run_id})")
}

/// The `--db` every command this report prints has to carry, ready to be
/// pasted into one, or nothing when a bare invocation finds the same database.
///
/// A next step the reader cannot take is worse than no next step at all: they
/// paste it, it opens somewhere else, and the report that sent them there is
/// the thing they stop trusting.
fn database_flag(report: &Report) -> String {
    report
        .run
        .replay_database
        .as_deref()
        .map_or_else(String::new, |path| format!(" --db {path}"))
}

/// What became of the groups the previous run put at the top.
///
/// Written beside the total rather than instead of it. The total is the right
/// measure of how much duplication a tree holds and the wrong measure of how
/// much of it anyone has dealt with: closing eighteen groups out of nine
/// thousand moves it by a rounding error.
///
/// `gone` says what it means on the same line, and the rest of the earlier top
/// is accounted for beside it. A number that names a subset without naming the
/// rule that selected it cannot be reconciled with a number the reader counted
/// themselves, and a reader who cannot reconcile two numbers trusts neither.
fn render_top_churn(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    let Some(churn) = &summary.top_churn else {
        return Ok(());
    };
    let top = thousands(churn.top);
    // Only the parts that happened are written: a zero here is a clause the
    // eye has to read and then dismiss. `more` is used only after a first
    // clause has established what it is more than.
    let mut left = Vec::new();
    if !churn.closed.is_empty() {
        left.push(format!(
            "{} of its top {top} groups are gone (no group holds their content now)",
            count(&churn.closed)
        ));
    }
    if !churn.superseded.is_empty() {
        left.push(if left.is_empty() {
            format!(
                "{} of its top {top} groups live on in a successor group",
                count(&churn.superseded)
            )
        } else {
            format!(
                "{} more live on in a successor group",
                count(&churn.superseded)
            )
        });
    }
    if !churn.outranked.is_empty() {
        left.push(if left.is_empty() {
            format!(
                "{} of its top {top} groups fell out of it",
                count(&churn.outranked)
            )
        } else {
            format!("{} only fell out of the top {top}", count(&churn.outranked))
        });
    }
    if !left.is_empty() {
        writeln!(out, "since run {}: {}", churn.since_run_id, left.join("; "))?;
    }
    let mut arrived = Vec::new();
    if !churn.entered.is_empty() {
        arrived.push(format!(
            "{} new groups entered the top {top}",
            count(&churn.entered)
        ));
    }
    if !churn.promoted.is_empty() {
        arrived.push(format!(
            "{} {}entered by taking over a group that was already there",
            count(&churn.promoted),
            if arrived.is_empty() { "" } else { "more " },
        ));
    }
    if arrived.is_empty() {
        return Ok(());
    }
    writeln!(
        out,
        "since run {}: {}",
        churn.since_run_id,
        arrived.join("; ")
    )
}

/// What one seam has cost, as the clauses that have something to say.
///
/// A zero is a clause the eye has to read and then dismiss, so a count of none
/// is written only where its absence is the answer: a seam crossed repeatedly
/// and never breached is exactly the case the ledger exists to tell apart from
/// one that costs a fix every time.
fn seam_clauses(seam: &ReportedSeam) -> Vec<String> {
    if seam.asymmetric_changes == 0 {
        // Nothing followed from a change that never happened, so the breach
        // and finding counts have no crossing to qualify.
        return vec!["no asymmetric changes".to_owned()];
    }
    let mut clauses = vec![plural(seam.asymmetric_changes, "asymmetric change")];
    if seam.breaches == 0 {
        clauses.push("no breaches".to_owned());
    } else {
        let last = seam
            .last_breach
            .as_deref()
            .map_or_else(String::new, |commit| {
                let abbreviated: String = commit.chars().take(ABBREVIATED_COMMIT).collect();
                format!(" (last {abbreviated})")
            });
        clauses.push(format!(
            "{} {}{last}",
            thousands(seam.breaches),
            noun_form_of(seam.breaches, "breach", "breaches"),
        ));
    }
    if seam.findings > 0 {
        clauses.push(plural(seam.findings, "finding"));
    }
    clauses
}

/// What moved for one seam since the previous generation, as the clauses that
/// moved.
///
/// A seam whose every count stands still contributes nothing: the line exists
/// to name what changed, and naming the rest beside it would bury it.
fn seam_delta_clauses(seam: &ReportedSeam) -> Vec<String> {
    let mut clauses = Vec::new();
    let counted = [
        (
            seam.asymmetric_changes_since,
            "asymmetric change",
            "asymmetric changes",
        ),
        (seam.breaches_since, "breach", "breaches"),
        (seam.findings_since, "finding", "findings"),
    ];
    for (delta, singular, plural_form) in counted {
        if let Some(delta) = delta.filter(|delta| *delta != 0) {
            let noun = if delta.unsigned_abs() == 1 {
                singular
            } else {
                plural_form
            };
            // Grouped the way the count above it is: a movement written
            // without the separators the figure it moved carries reads as a
            // different kind of number.
            let sign = if delta < 0 { '-' } else { '+' };
            clauses.push(format!("{sign}{} {noun}", thousands(delta.unsigned_abs())));
        }
    }
    clauses
}

/// The singular or plural of a noun whose plural is not its singular and an
/// `s`.
const fn noun_form_of<'a>(count: u64, singular: &'a str, plural_form: &'a str) -> &'a str {
    if count == 1 { singular } else { plural_form }
}

/// How many things are in a list, written the way every other count is.
fn count(entries: &[String]) -> String {
    thousands(u64::try_from(entries.len()).unwrap_or(u64::MAX))
}

/// An elapsed time, at the precision a reader can act on.
///
/// Tenths below a minute and whole seconds above it: nobody arranges reuse
/// over a hundredth of a second, and nobody reads four significant figures of
/// a five-minute scan.
fn seconds(elapsed: std::time::Duration) -> String {
    let value = elapsed.as_secs_f64();
    if value < 60.0 {
        format!("{value:.1}s")
    } else {
        format!("{}s", thousands(elapsed.as_secs()))
    }
}

/// Totals for serialized supplemental evidence that the default body hides.
///
/// Counts come from the final vectors, while cap notes come from the recorded
/// funnel. A configured ceiling that dropped nothing is not mentioned.
fn render_supplemental_totals(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    let sibling_drops = funnel_drop_count(
        summary,
        &[
            FunnelCause::SiblingCandidateBudget,
            FunnelCause::SiblingPerGroupCap,
            FunnelCause::SiblingTotalCap,
            FunnelCause::SignatureSiblingCandidateBudget,
            FunnelCause::SignatureSiblingPerGroupCap,
            FunnelCause::SignatureSiblingTotalCap,
        ],
    );
    let near_miss_drops = funnel_drop_count(summary, &[FunnelCause::RetentionCap]);
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

/// What the named causes dropped between them, summed.
///
/// Causes are named as the values they are rather than as the strings a
/// recorded funnel spells them with: a caller asking for a cause that no
/// longer exists then fails to compile, instead of quietly matching nothing
/// and reporting that a ceiling dropped nobody.
fn funnel_drop_count(summary: &Summary, causes: &[FunnelCause]) -> u64 {
    summary
        .funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| {
            FunnelCause::from_name(&drop.cause).is_some_and(|cause| causes.contains(&cause))
        })
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
        ("build metadata too large", excluded.oversized_metadata),
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

/// One compiler-coverage gap spelled out reason by reason, in the same
/// vocabulary the JSON report uses.
fn by_reason(counts: &std::collections::BTreeMap<String, u64>) -> String {
    counts
        .iter()
        .map(|(reason, count)| format!("{count} {reason}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The ceilings this run analysed under, and the ones its diagnostics used.
///
/// Only what the recorded run actually held itself to. A mode leaves the
/// ceilings its stages never consult absent (see [`Guardrails`]), and a line
/// naming one of those would tell a reader to lower a number no stage of this
/// run ever read.
fn render_guardrails(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
    let Some(guardrails) = &summary.guardrails else {
        return Ok(());
    };
    let mut applied = vec![
        format!("files over {} bytes skipped", guardrails.max_file_bytes),
        format!(
            "parse work capped at min(file ceiling, {} ms × {} bytes)",
            guardrails.parse_timeout_ms,
            crate::scan::runtime::PARSE_BYTES_PER_MILLISECOND,
        ),
        format!("{} ms helper deadline", guardrails.helper_timeout_ms),
        format!("posting lists up to {}", guardrails.posting_cap),
        format!("{} candidate pairs per pass", guardrails.pair_budget),
    ];
    if let Some(pairs) = guardrails.verification_budget {
        applied.push(format!("{pairs} verification pairs"));
    }
    if let Some(cells) = guardrails.max_alignment_cells {
        applied.push(format!("{cells} cells per alignment"));
    }
    if let Some(units) = guardrails.max_component {
        applied.push(format!("{units} units per group"));
    }
    writeln!(
        out,
        "  {} profile: {}",
        guardrails.profile,
        applied.join(", "),
    )?;
    let mut diagnostics = Vec::new();
    if let Some((band, cap)) = guardrails.near_miss_delta.zip(guardrails.near_miss_cap) {
        diagnostics.push(format!("near-match band {band}, at most {cap} near misses"));
    }
    if let (Some(budget), Some(per_group), Some(total)) = (
        guardrails.sibling_candidate_budget,
        guardrails.sibling_per_group_cap,
        guardrails.sibling_total_cap,
    ) {
        diagnostics.push(format!(
            "sibling sweep {budget} comparisons, {per_group} per group, {total} total"
        ));
    }
    if summary
        .funnel
        .iter()
        .any(|stage| stage.stage == "signature sibling entries")
        && let (Some(budget), Some(per_group), Some(total)) = (
            guardrails.signature_sibling_candidate_budget,
            guardrails.signature_sibling_per_group_cap,
            guardrails.signature_sibling_total_cap,
        )
    {
        diagnostics.push(format!(
            "signature sibling sweep {budget} candidates, {per_group} per group, {total} total"
        ));
    }
    if diagnostics.is_empty() {
        return Ok(());
    }
    writeln!(out, "  diagnostics: {}", diagnostics.join("; "))
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
const ARTIFACT_GUIDANCE: &str = "note: no artifact savings are recorded; run artifact analyze <PATH> --source-run <id> --build-variant <manifest> on a build of this tree, supplying the evidence its format carries:";

/// One guidance line per format, stating what to supply and how precisely the
/// result can be attributed back to source.
///
/// The attribution each line promises is derived from the artifact crate's
/// format support definitions -- the same definitions every backend declares
/// its capabilities from -- rather than restated here. A format reaches a
/// clone group's line range only when its parses attach source line frames to
/// symbols; a format that merely names symbols says so, and says why, instead
/// of pointing at a condition it cannot meet. A format added to the boundary
/// therefore gets a line without this note being edited.
fn artifact_guidance_lines() -> Vec<String> {
    codehelion_artifact::FORMAT_SUPPORT
        .iter()
        .map(|support| {
            let evidence = support.source_evidence;
            let detail = match support.attribution() {
                codehelion_artifact::SourceAttribution::LineRange => format!(
                    "supply {}, or a matching companion via --debug-file <PATH>; clone-group line ranges are then attributed",
                    evidence.carrier
                ),
                codehelion_artifact::SourceAttribution::Symbol => format!(
                    "{} attributes whole symbols only; {}",
                    evidence.symbol_carrier,
                    evidence
                        .line_limit
                        .unwrap_or("clone-group line ranges are not attributable"),
                ),
                codehelion_artifact::SourceAttribution::None => {
                    "no source correspondence is available; sizes and duplicates are still reported"
                        .to_owned()
                }
            };
            format!("  {}: {detail}", support.format)
        })
        .collect()
}

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

fn write_artifact_guidance(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{ARTIFACT_GUIDANCE}")?;
    for line in artifact_guidance_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

fn render_artifact_guidance(report: &Report, out: &mut impl Write) -> io::Result<()> {
    if report.run.run_id.is_none() {
        return Ok(());
    }
    if !artifact_guidance_needed(report.groups.iter()) {
        return Ok(());
    }
    write_artifact_guidance(out)
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
    write_artifact_guidance(out)
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
/// How a group stands relative to the run before it.
///
/// Written only where there is a comparison to report: a group with no
/// predecessor connection says nothing here, and a first scan says nothing at
/// all. An adoption names the group it took over from and the shared member
/// contents the connection was decided on, because that count is the rule
/// itself.
///
/// The count is stated out of the population it was counted in — the group's
/// distinct member contents, of which several members can share one — and
/// alone when the recorded connection measured no population. The group's
/// member count is a different population, and dividing by it would present
/// strong evidence as weak.
fn render_group_identity(group: &Group, indent: &str, out: &mut impl Write) -> io::Result<()> {
    let Some(identity) = &group.identity else {
        return Ok(());
    };
    if identity.origin == IDENTITY_ADOPTED {
        let from = identity.adopted_from.as_deref().unwrap_or("");
        let shared = identity.shared_members.unwrap_or(0);
        return match identity.compared_members {
            Some(compared) => writeln!(
                out,
                "{indent}  new identity (lineage: {from}, {shared} of {compared} member \
                 content(s) shared)",
            ),
            None => writeln!(
                out,
                "{indent}  new identity (lineage: {from}, {shared} member content(s) shared)",
            ),
        };
    }
    if identity.origin == IDENTITY_RETAINED {
        return writeln!(
            out,
            "{indent}  identity retained from run {}",
            identity.compared_with_run,
        );
    }
    Ok(())
}

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
fn group_markers(group: &Group, opts: TextOptions, palette: &Palette) -> String {
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
    // Cuts of one stretch are separate findings that say different things, so
    // both are listed; read in order they are otherwise two entries about the
    // same lines with nothing on either saying so.
    let cut = group
        .narrower_cut_of
        .as_ref()
        .map_or_else(String::new, |wider| {
            format!(
                " {}",
                palette.yellow(&format!("[narrower cut of {}]", opts.id(wider)))
            )
        });
    format!("{}{overlap}{cut}{marker}", baseline_marker(group, palette))
}

/// The occurrences one group writes, canonical first.
///
/// The canonical occurrence leads because it is the one the group is measured
/// against and the one a reader opens first; every other order makes that a
/// fact you have to look for.
fn listed_members(group: &Group, opts: TextOptions) -> Vec<(bool, &Member)> {
    let anchor = canonical_position(&group.members, |member| member.canonical).unwrap_or(0);
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
        group_markers(group, opts, palette),
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
    render_group_identity(group, indent, out)?;
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
            "        source build variant digest: {}",
            savings.source_build_variant_fingerprint
        )?;
        writeln!(
            out,
            "        artifact build variant digest: {}",
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod artifact_guidance_tests {
    use super::{ARTIFACT_GUIDANCE, artifact_guidance_lines, write_artifact_guidance};
    use codehelion_artifact::{FORMAT_SUPPORT, SourceAttribution};

    fn rendered() -> String {
        let mut out = Vec::new();
        write_artifact_guidance(&mut out).expect("guidance renders");
        String::from_utf8(out).expect("guidance is text")
    }

    /// Every format the boundary reads gets a line, so a format added later
    /// cannot leave the note describing only the formats that existed before.
    #[test]
    fn the_note_covers_every_format_the_boundary_reads() {
        let note = rendered();
        assert!(note.starts_with(ARTIFACT_GUIDANCE), "{note}");
        assert_eq!(artifact_guidance_lines().len(), FORMAT_SUPPORT.len());
        for support in &FORMAT_SUPPORT {
            assert!(
                note.contains(&format!("  {}: ", support.format)),
                "{} has no line: {note}",
                support.format
            );
        }
    }

    /// A module whose only symbol evidence is the name section is told what
    /// that reaches -- whole symbols -- and why a clone group's line range is
    /// not among it, rather than being asked for debug information that would
    /// change the size it is being asked about.
    #[test]
    fn the_wasm_line_promises_symbols_and_names_the_line_range_limit() {
        let note = rendered();
        let line = note
            .lines()
            .find(|line| line.trim_start().starts_with("wasm: "))
            .expect("wasm has a line");

        assert!(line.contains("the name section"), "{line}");
        assert!(line.contains("attributes whole symbols only"), "{line}");
        assert!(line.contains("DWARF"), "{line}");
        assert!(line.contains("changes the size being measured"), "{line}");
        assert!(
            !line.contains("clone-group line ranges are then attributed"),
            "{line}"
        );
    }

    /// A format that reaches a source line is told what to supply for it, and
    /// only such a format is promised clone-group attribution.
    #[test]
    fn only_a_format_that_reaches_a_source_line_is_promised_line_attribution() {
        let note = rendered();
        for support in &FORMAT_SUPPORT {
            let prefix = format!("  {}: ", support.format);
            let line = note
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("{} has a line", support.format));
            let promises_lines = line.contains("clone-group line ranges are then attributed");
            assert_eq!(
                promises_lines,
                support.attribution() == SourceAttribution::LineRange,
                "{} promises the wrong granularity: {line}",
                support.format
            );
            if promises_lines {
                assert!(
                    line.contains(support.source_evidence.carrier),
                    "{} does not name what to supply: {line}",
                    support.format
                );
            }
        }
    }

    /// The note names the state it is printed in and the command that leaves
    /// it, so a reader whose groups all report unavailable attribution is told
    /// what that state is rather than being contradicted by the note.
    #[test]
    fn the_note_names_the_state_it_reports_and_the_command_that_leaves_it() {
        let note = rendered();
        assert!(note.contains("no artifact savings are recorded"), "{note}");
        assert!(
            note.contains("artifact analyze <PATH> --source-run <id> --build-variant <manifest>"),
            "{note}"
        );
        // A report with nothing to attribute must not be told that something
        // was attributed.
        assert!(!note.contains("attributed bytes"), "{note}");
        // A run with no groups has nothing to correlate, so it gets no note.
        assert!(!super::artifact_guidance_needed(std::iter::empty()));
    }
}
