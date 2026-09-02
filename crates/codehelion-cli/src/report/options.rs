//! What the text view is allowed to draw and how much of it to show.

use super::{SHORT_ID_CHARS, Sort, TEXT_GROUP_LIMIT, TEXT_MEMBER_LIMIT};

/// The glyph set a text report draws its structure with.
///
/// Separate from colour because the two fail in different places: colour is
/// wrong when the destination is not a terminal, glyphs are wrong when the
/// terminal cannot draw them. A log viewer that renders box-drawing characters
/// as replacement squares still renders colour perfectly well.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Decoration {
    /// Box-drawing characters and symbols.
    #[default]
    Unicode,
    /// ASCII stand-ins for every glyph.
    Ascii,
    /// No tree and no marks: indentation alone, for a destination that should
    /// carry no structure it has to look past.
    None,
}

impl Decoration {
    /// The branch drawn before an occurrence that is not the last one.
    pub(crate) const fn branch(self) -> &'static str {
        match self {
            Self::Unicode => "├─ ",
            Self::Ascii => "|- ",
            Self::None => "   ",
        }
    }

    /// The branch drawn before the last occurrence under a group.
    pub(crate) const fn last_branch(self) -> &'static str {
        match self {
            Self::Unicode => "└─ ",
            Self::Ascii => "`- ",
            Self::None => "   ",
        }
    }

    /// The mark on the occurrence a group is measured against.
    pub(crate) const fn canonical(self) -> &'static str {
        match self {
            Self::Unicode => "◆",
            Self::Ascii => "*",
            Self::None => "",
        }
    }

    /// The mark on a line that qualifies the whole run.
    pub(crate) const fn warning(self) -> &'static str {
        match self {
            Self::Unicode => "⚠ ",
            Self::Ascii => "! ",
            Self::None => "",
        }
    }

    /// The multiplication sign before an occurrence count.
    pub(crate) const fn times(self) -> &'static str {
        match self {
            Self::Unicode => "×",
            Self::Ascii | Self::None => "x",
        }
    }

    /// What separates the parts of a one-line heading.
    pub(crate) const fn separator(self) -> &'static str {
        match self {
            Self::Unicode => "·",
            Self::Ascii | Self::None => "|",
        }
    }

    /// What stands between the two sides of a comparison.
    pub(crate) const fn between(self) -> &'static str {
        match self {
            Self::Unicode => "↔",
            Self::Ascii | Self::None => "<->",
        }
    }
}

/// Rendering options for the text view of a [`Report`](super::Report).
#[allow(
    clippy::struct_excessive_bools,
    reason = "each boolean is an independent presentation option mirrored by a CLI flag"
)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    /// How much is written about each group: `0` lists them, `1` adds the
    /// ranking inputs and what the scan read, `2` adds run diagnostics and
    /// full identifiers.
    pub verbosity: u8,
    /// Print the groups alone, without the heading, the summary, or the notes.
    pub quiet: bool,
    /// Groups the listing prints, and occurrences it prints per group.
    /// `None` applies the defaults; `Some(0)` prints every one of both.
    pub limit: Option<usize>,
    /// Emit ANSI colour codes.
    pub color: bool,
    /// The glyph set the listing draws its structure with.
    pub decoration: Decoration,
    /// Also list suppressed groups, with the reason each was hidden.
    pub show_suppressed: bool,
    /// Also list incomplete local mirrors attached to visible primary groups.
    pub show_siblings: bool,
    /// Also list run-scoped LSH diagnostics that narrowly missed the primary
    /// candidate threshold.
    pub show_near_misses: bool,
    /// The axis the report was put in order on, for the listing's heading.
    pub sort: Sort,
    /// Leave groups whose raw identifier agreement is below this out of the
    /// listing, saying how many were left out.
    ///
    /// A view, not a rule: nothing is recorded, no count moves, and the same
    /// run rendered without it lists everything. It exists because a reader
    /// working maintainability picks a floor on this measure and works down
    /// from there, and doing it by hand means leaving the tool.
    pub min_identifier_jaccard: Option<f64>,
}

impl TextOptions {
    /// Whether the reader asked for the numbers behind each group.
    #[must_use]
    pub(crate) const fn detailed(self) -> bool {
        self.verbosity >= 1
    }

    /// Whether the reader asked for what the run itself did, rather than what
    /// it found.
    #[must_use]
    pub(crate) const fn diagnostic(self) -> bool {
        self.verbosity >= 2
    }

    /// Groups the listing prints before saying how many it left out.
    pub(crate) const fn group_limit(self) -> usize {
        match self.limit {
            None => TEXT_GROUP_LIMIT,
            Some(0) => usize::MAX,
            Some(limit) => limit,
        }
    }

    /// Occurrences printed under one group.
    pub(crate) const fn member_limit(self) -> usize {
        match self.limit {
            Some(0) => usize::MAX,
            _ => TEXT_MEMBER_LIMIT,
        }
    }

    /// A fingerprint as this view prints it: abbreviated to the shortest
    /// prefix `codehelion explain` accepts, unless full identifiers were
    /// asked for.
    pub(crate) fn id(self, hex: &str) -> &str {
        if self.diagnostic() {
            hex
        } else {
            hex.get(..SHORT_ID_CHARS).unwrap_or(hex)
        }
    }
}
