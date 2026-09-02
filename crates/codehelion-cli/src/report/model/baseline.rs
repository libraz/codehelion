//! Baseline-relative report records and the counts of what a scan left out.

use serde::Serialize;

/// What a baseline did to this run's findings.
///
/// An entry that matched nothing is reported rather than left implicit, and
/// it is deliberately not phrased as a problem: a baseline going stale is a
/// duplication that got fixed. The number is what tells the reader that
/// `baseline update` has something to drop.
///
#[derive(Debug, Clone, Serialize)]
pub struct BaselineStatus {
    /// The baseline file, as it was given on the command line.
    pub file: String,
    /// Entries the file holds.
    pub entries: u64,
    /// What the run was told to do with the entries: [`BASELINE_SUPPRESS`](crate::report::BASELINE_SUPPRESS) to
    /// hide the findings they froze, [`BASELINE_COMPARE`](crate::report::BASELINE_COMPARE) to hide nothing and
    /// report each group against them instead.
    pub mode: String,
    /// Entries whose group identity this run still reports.
    pub matched: u64,
    /// Entries that hid nothing, the duplication they covered being gone.
    pub stale: u64,
    /// Groups this run reports that the baseline never froze.
    pub appeared: u64,
    /// Frozen groups that now have more occurrences than were covered.
    pub expanded: u64,
    /// Occurrences added across the expanded groups.
    pub expanded_instances: u64,
    /// Tokens the stale entries repeated when they were frozen.
    pub stale_tokens: u64,
    /// Tokens the groups that appeared repeat now.
    ///
    /// Reported beside [`stale_tokens`](Self::stale_tokens) because a count of
    /// groups says nothing about size: removing one large duplication that
    /// leaves three small ones behind is progress that reads as a regression
    /// until both numbers are on the page.
    pub appeared_tokens: u64,
    /// Repeated tokens added across expanded groups.
    pub expanded_tokens: u64,
    /// Every stale entry, so that what was removed can be read rather than
    /// only counted.
    pub gone: Vec<GoneGroup>,
}

/// A baseline entry whose duplication this run no longer reports.
#[derive(Debug, Clone, Serialize)]
pub struct GoneGroup {
    /// Hex group fingerprint the baseline froze.
    pub group: String,
    /// The entry's clone classification.
    pub clone_type: String,
    /// Tokens it repeated when it was frozen.
    pub duplicated_tokens: u64,
    /// Where its canonical occurrence sat, as the baseline recorded it. The
    /// code is gone, so this describes where to remember it from rather than
    /// where to look now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<GoneAnchor>,
}

/// Where a gone entry's canonical occurrence sat.
#[derive(Debug, Clone, Serialize)]
pub struct GoneAnchor {
    /// Path relative to the scan root.
    pub file: String,
    /// 1-based first line.
    pub start_line: i64,
    /// 1-based last line.
    pub end_line: i64,
    /// Name of the enclosing unit, when it had one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// What a baseline the run was given says about one group.
#[derive(Debug, Clone, Serialize)]
pub struct GroupBaseline {
    /// `continuing` when the baseline froze this group, `new` when it did not,
    /// or `expanded` when it has additional uncovered occurrences.
    pub state: String,
    /// Occurrences beyond the baseline's covered count, for an expanded
    /// group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_instances: Option<u64>,
    /// The gone entry this group stands in place of, when one can be named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<Derivation>,
}

/// The gone entry a group appears to have re-formed from.
#[derive(Debug, Clone, Serialize)]
pub struct Derivation {
    /// Hex group fingerprint of the gone entry.
    pub group: String,
    /// How many of this group's occurrences sit where that entry's did.
    pub shared_sites: u64,
}

/// Files the scan dropped, by cause. Nothing is omitted silently.
#[derive(Debug, Serialize)]
pub struct ExcludedCounts {
    /// Files excluded for carrying a generated-code marker.
    pub generated: u64,
    /// Files excluded by the configured include/exclude globs.
    pub by_glob: u64,
    /// Files skipped for other causes (size, binary content, read errors).
    pub skipped: u64,
    /// Source files over the configured size ceiling.
    pub too_large: u64,
    /// Recognised build-metadata files over that same ceiling.
    ///
    /// Named apart from [`Self::too_large`] because it costs the run something
    /// else: a compilation database or manifest left unread describes a build
    /// nothing else in the tree describes, so the findings that depended on it
    /// are missing for a reason no count of skipped sources explains.
    pub oversized_metadata: u64,
    /// Files identified as binary before parsing.
    pub binary: u64,
    /// Files the walker or frontend could not read.
    pub unreadable: u64,
    /// Symbolic links deliberately left unresolved by the source walker.
    pub symlinks: u64,
    /// Directory entries the source walker could not read.
    pub walk_errors: u64,
    /// Files that exceeded the parse-time allowance.
    pub timed_out: u64,
    /// Files excluded because their language was disabled for the scan.
    pub language_excluded: u64,
    /// Symbolic-link files deliberately left unresolved by the source walker.
    pub symlink_files: u64,
    /// Symbolic-link directories deliberately left unresolved by the source walker.
    pub symlink_directories: u64,
}

impl ExcludedCounts {
    pub(in crate::report) const fn total(&self) -> u64 {
        self.generated
            .saturating_add(self.by_glob)
            .saturating_add(self.too_large)
            .saturating_add(self.oversized_metadata)
            .saturating_add(self.binary)
            .saturating_add(self.unreadable)
            .saturating_add(self.language_excluded)
            .saturating_add(self.symlinks)
            .saturating_add(self.walk_errors)
            .saturating_add(self.timed_out)
    }
}

/// How much of the source the parser could not follow.
///
/// A parser that recovers keeps going, so a file it could not follow still
/// produces units and still reaches detection — the difference is that those
/// units describe error recovery rather than the code. Without this the two
/// are indistinguishable in a report: a scan that read a tenth of a project
/// looks exactly like a scan that read all of it and found little.
///
/// The measure is tokens rather than bytes, and it excludes what recovery
/// salvaged. Recovery routinely opens one error region around far more than
/// the construct that caused it, so the region's extent is not a measure of
/// anything; see [`SyntaxIrFile::unaccounted_tokens`].
///
/// [`SyntaxIrFile::unaccounted_tokens`]: codehelion_core::ir::SyntaxIrFile::unaccounted_tokens
#[derive(Debug, Serialize)]
pub struct UnparsedCounts {
    /// Files holding at least one token the parser could not attach to any
    /// structure.
    pub files: u64,
    /// How many such tokens there are.
    pub tokens: u64,
    /// Those tokens as a share of every analysed token, rounded to four
    /// places.
    pub share: f64,
}

impl UnparsedCounts {
    /// Tally the unaccounted tokens `per_file` against `total` analysed
    /// tokens.
    #[must_use]
    pub fn new(per_file: impl IntoIterator<Item = u64>, total: u64) -> Self {
        let mut files = 0;
        let mut unparsed = 0;
        for tokens in per_file {
            if tokens > 0 {
                files += 1;
                unparsed += tokens;
            }
        }
        Self::from_counts(files, unparsed, total)
    }

    /// The same tally from counts already taken, as a stored run carries them.
    ///
    /// The share is recomputed rather than stored: it is a ratio of two numbers
    /// on the row, and a third column holding their quotient is one more thing
    /// that can disagree with them.
    #[must_use]
    pub fn from_counts(files: u64, tokens: u64, total: u64) -> Self {
        // Ratios of counts this size lose nothing that a report shows.
        #[allow(clippy::cast_precision_loss)]
        let share = if total == 0 {
            0.0
        } else {
            ((tokens as f64 / total as f64) * 10_000.0).round() / 10_000.0
        };
        Self {
            files,
            tokens,
            share,
        }
    }
}
