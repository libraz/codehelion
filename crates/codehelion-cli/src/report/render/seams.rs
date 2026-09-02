//! The seam-ledger section of the text report.

use super::format::{noun_form_of, plural, thousands};
use super::{ABBREVIATED_COMMIT, Palette};
use crate::report::{Report, ReportedSeam};
use std::io;
use std::io::Write;

impl Report {
    /// What the seams written into the ledger have cost, and what moved since
    /// the generation before this one.
    ///
    /// Read from a recorded `codehelion seam` run, so a report that has none
    /// says nothing rather than a row of zeroes: a ledger nobody has evaluated
    /// is not a ledger whose seams cost nothing.
    pub(super) fn render_seams(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
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
}

/// What one seam has cost, as the clauses that have something to say.
///
/// A zero is a clause the eye has to read and then dismiss, so a count of none
/// is written only where its absence is the answer: a seam crossed repeatedly
/// and never breached is exactly the case the ledger exists to tell apart from
/// one that costs a fix every time.
pub(super) fn seam_clauses(seam: &ReportedSeam) -> Vec<String> {
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
pub(super) fn seam_delta_clauses(seam: &ReportedSeam) -> Vec<String> {
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
