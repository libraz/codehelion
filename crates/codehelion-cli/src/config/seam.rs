//! The seam ledger a project writes down, and the thresholds the seam
//! analysis is computed under.

use serde::{Deserialize, Serialize};

/// One seam, as the ledger in `codehelion.toml` writes it.
///
/// A seam is a set of paths that implement the same semantics and have been
/// changed together, and this is where a project writes down that it has one.
/// Nothing here is inferred: the ledger is the source of truth for what `guard`
/// judges, because a subject recomputed from history each day would make the
/// same change pass today and fail tomorrow with nothing between the two but
/// somebody else's commits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SeamLedgerEntry {
    /// Name this seam is reported under. Chosen by a person, and stable.
    pub id: String,
    /// Path globs, in the syntax `[suppression] paths` already uses. At least
    /// two: a seam of one member has nothing to be asymmetric about.
    pub members: Vec<String>,
    /// What the seam is, for whoever reads the report. Nothing reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Thresholds the seam analysis is computed under.
///
/// Spelled `[seam-tracking]` rather than `[seam]` because the ledger above
/// already claims that name as an array of tables, and TOML gives one name to
/// one shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct SeamTracking {
    /// How many commits after an asymmetric change a `fix` still counts as a
    /// breach of it. Counted in commits rather than in time: it is meant to
    /// cover one piece of work, and a clock would make the answer depend on
    /// when somebody took a weekend.
    pub breach_window: usize,
    /// Ceiling on how many commits are read, newest first.
    pub history_limit: usize,
    /// Commits touching more paths than this are left out of coupling. They
    /// stay in breach detection: a sweeping commit that broke a seam broke it.
    pub max_commit_size: usize,
    /// Lowest coupling `--suggest` will propose a pair at.
    pub min_coupling: f64,
    /// Fewest shared commits `--suggest` will propose a pair on.
    pub min_support: usize,
    /// How many leading path components make the unit `--suggest` counts
    /// co-change over. A file is too fine to see a pair of parallel
    /// implementations in; the whole tree is too coarse to see anything.
    pub suggest_depth: usize,
}

impl Default for SeamTracking {
    fn default() -> Self {
        let settings = codehelion_seam::Settings::default();
        Self {
            breach_window: settings.breach_window,
            history_limit: settings.history_limit,
            max_commit_size: settings.max_commit_size,
            min_coupling: settings.min_coupling,
            min_support: settings.min_support,
            suggest_depth: settings.suggest_depth,
        }
    }
}

impl SeamTracking {
    /// These settings as the seam analysis reads them.
    #[must_use]
    pub const fn settings(&self) -> codehelion_seam::Settings {
        codehelion_seam::Settings {
            breach_window: self.breach_window,
            history_limit: self.history_limit,
            max_commit_size: self.max_commit_size,
            min_coupling: self.min_coupling,
            min_support: self.min_support,
            suggest_depth: self.suggest_depth,
        }
    }
}
