//! The heading, totals, legend, inputs and pipeline sections of the text
//! report: what the run was and what it read.

use super::Palette;
use super::format::{count, plural, seconds, thousands};
use super::notes::{render_baseline_detail, render_guardrails, render_helper_diagnostics};
use crate::report::{FunnelCause, Group, Report, SCOPE_FRAGMENT, Summary, TextOptions};
use std::io;
use std::io::Write;

impl Report {
    /// Write what the reader has to know before reading a single number:
    /// which tree, in which mode, and — when asked — under what settings.
    pub(super) fn render_heading(
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
    pub(super) fn render_totals(
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
    pub(super) fn reported(&self) -> Vec<&Group> {
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
    pub(super) fn visible(&self, opts: TextOptions) -> Vec<&Group> {
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
    pub(super) fn render_legend(
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
    pub(super) fn render_composition_detail(&self, out: &mut impl Write) -> io::Result<()> {
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

    /// The stage-by-stage pass counts, wide enough to be read as a column.
    pub(super) fn render_funnel(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
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
    pub(super) fn render_inputs(&self, opts: TextOptions, out: &mut impl Write) -> io::Result<()> {
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
    pub(super) fn render_timings(&self, out: &mut impl Write) -> io::Result<()> {
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

    pub(super) fn render_configuration(&self, out: &mut impl Write) -> io::Result<()> {
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
}

/// The group total broken down by clone type, leaving out the types this mode
/// cannot report.
pub(super) fn run_status(report: &Report) -> String {
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
pub(super) fn database_flag(report: &Report) -> String {
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
pub(super) fn render_top_churn(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
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

/// Totals for serialized supplemental evidence that the default body hides.
///
/// Counts come from the final vectors, while cap notes come from the recorded
/// funnel. A configured ceiling that dropped nothing is not mentioned.
pub(super) fn render_supplemental_totals(
    summary: &Summary,
    out: &mut impl Write,
) -> io::Result<()> {
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
pub(super) fn render_common_signatures(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
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
pub(super) fn funnel_drop_count(summary: &Summary, causes: &[FunnelCause]) -> u64 {
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

pub(super) fn group_composition(summary: &Summary) -> String {
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
pub(super) fn excluded_causes(summary: &Summary) -> Vec<String> {
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
pub(super) fn by_reason(counts: &std::collections::BTreeMap<String, u64>) -> String {
    counts
        .iter()
        .map(|(reason, count)| format!("{count} {reason}"))
        .collect::<Vec<_>>()
        .join(", ")
}
