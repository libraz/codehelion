//! Notes about the run itself: ceilings that applied, evidence the mode
//! could not produce, and what an artifact analysis would add.

use super::format::thousands;
use super::groups::render_gone;
use crate::report::{
    BaselineStatus, Group, Report, Summary, TextOptions, UnusedRule, budget_note,
    depth_truncation_files, nesting_truncation_bodies, search_truncation_note, severed_note,
};
use std::io;
use std::io::Write;

impl Report {
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

    pub(super) fn render_notes_with_artifact_guidance(
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
}

/// What a signature-channel sibling's evidence is worth, in the words every
/// text view says it in.
///
/// How many units share the signature is the whole strength of this channel: a
/// signature held by a handful of units says something, and one the whole layer
/// shares says nothing. The number is shown so the reader can tell those apart;
/// it never moves the confidence band. `None` is a sibling from the similarity
/// channel, whose evidence is the score alone.
pub(in crate::report) fn signature_note(
    basis: &str,
    signature_units: Option<u64>,
) -> Option<String> {
    match (basis, signature_units) {
        ("signature", Some(units)) => Some(format!(
            "[same signature, {} units share it]",
            thousands(units)
        )),
        ("signature", None) => Some("[same signature]".to_owned()),
        _ => None,
    }
}

/// The ceilings this run analysed under, and the ones its diagnostics used.
///
/// Only what the recorded run actually held itself to. A mode leaves the
/// ceilings its stages never consult absent (see [`Guardrails`](crate::report::Guardrails)), and a line
/// naming one of those would tell a reader to lower a number no stage of this
/// run ever read.
pub(super) fn render_guardrails(summary: &Summary, out: &mut impl Write) -> io::Result<()> {
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
pub(super) fn render_baseline_detail(
    baseline: &BaselineStatus,
    out: &mut impl Write,
) -> io::Result<()> {
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

pub(super) fn render_helper_diagnostics(
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
pub(super) fn render_unapplied_suppression_policies(
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
pub(super) fn render_unmeasured_in_this_mode(
    summary: &Summary,
    out: &mut impl Write,
) -> io::Result<()> {
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
pub(super) const ARTIFACT_GUIDANCE: &str = "note: no artifact savings are recorded; run artifact analyze <PATH> --source-run <id> --build-variant <manifest> on a build of this tree, supplying the evidence its format carries:";

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
pub(super) fn artifact_guidance_lines() -> Vec<String> {
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

pub(super) fn artifact_guidance_needed<'a>(groups: impl Iterator<Item = &'a Group>) -> bool {
    let mut has_group = false;
    for group in groups {
        has_group = true;
        if !group.artifact_savings.is_empty() {
            return false;
        }
    }
    has_group
}

pub(super) fn write_artifact_guidance(out: &mut impl Write) -> io::Result<()> {
    writeln!(out, "{ARTIFACT_GUIDANCE}")?;
    for line in artifact_guidance_lines() {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

pub(super) fn render_artifact_guidance(report: &Report, out: &mut impl Write) -> io::Result<()> {
    if report.run.run_id.is_none() {
        return Ok(());
    }
    if !artifact_guidance_needed(report.groups.iter()) {
        return Ok(());
    }
    write_artifact_guidance(out)
}

/// Render artifact guidance once for a partitioned report envelope.
pub(in crate::report) fn render_partition_artifact_guidance(
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
