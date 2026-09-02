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

use super::{Group, Report, TextOptions, Write, duplicated_tokens, io};

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
}

mod format;
mod groups;
mod notes;
mod seams;
mod summary;

use format::{decimal_width, member_location, thousands, width};
use groups::{group_kind, listed_members};

pub(super) use groups::render_group;
pub(super) use notes::{render_partition_artifact_guidance, signature_note};
