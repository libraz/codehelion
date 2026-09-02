//! The group listing and the supplemental listings drawn beside it.

use super::format::{member_location, member_unit, noun_form, pad, remaining, thousands, width};
use super::notes::signature_note;
use super::{GroupColumns, Palette};
use crate::report::{
    ArtifactSavings, BASELINE_COMPARE, BaselineStatus, Decoration, GONE_LISTED, GROUP_EXPANDED,
    GROUP_NEW, Group, IDENTITY_ADOPTED, IDENTITY_RETAINED, Member, Report, SCOPE_FRAGMENT,
    TextOptions, canonical_position, duplicated_tokens,
};
use std::io;
use std::io::Write;

impl Report {
    pub(super) fn render_groups(
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
    pub(super) fn render_near_misses(
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
    pub(super) fn render_siblings(
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

/// List what the baseline froze that this run no longer reports.
///
/// Only in compare mode: suppress mode is being asked to hide known
/// duplication, and a list of duplication that is no longer there is not what
/// it was asked for. The JSON report carries the list either way.
pub(super) fn render_gone(baseline: &BaselineStatus, out: &mut impl Write) -> io::Result<()> {
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
pub(super) fn baseline_marker(group: &Group, palette: &Palette) -> String {
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
pub(super) fn render_group_identity(
    group: &Group,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
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

pub(super) fn render_group_baseline(
    group: &Group,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
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
pub(super) fn group_kind(group: &Group, decoration: Decoration) -> String {
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
pub(super) fn group_markers(group: &Group, opts: TextOptions, palette: &Palette) -> String {
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
pub(super) fn listed_members(group: &Group, opts: TextOptions) -> Vec<(bool, &Member)> {
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
pub(super) fn canonical_mark(canonical: bool, decoration: Decoration) -> String {
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
pub(in crate::report) fn render_group(
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
pub(super) fn render_group_detail(
    group: &Group,
    indent: &str,
    out: &mut impl Write,
) -> io::Result<()> {
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
pub(super) fn render_group_members(
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
pub(super) fn member_trailing(
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
pub(super) fn render_artifact_savings(
    savings: &[ArtifactSavings],
    out: &mut impl Write,
) -> io::Result<()> {
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
