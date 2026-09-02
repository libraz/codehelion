//! Evaluates a written-down seam ledger against a repository's history.
//!
//! A *seam* is one piece of meaning implemented in more than one place, whose
//! copies have in fact been changed together. An *asymmetric change* is a
//! commit that moved some of those places and not the rest; a *breach* is an
//! asymmetric change followed, within a fixed window of commits, by a `fix:`
//! landing on one of the places it left behind. The breach is what makes the
//! seam worth naming: it is the recorded moment where leaving half the seam
//! alone cost something.
//!
//! # Why the ledger is the source of truth
//!
//! Which paths form a seam is read from the `[[seam]]` entries somebody wrote
//! and committed, never inferred from the history being measured. Inference
//! would make the set of watched seams a function of the history's length, so
//! a change that touched nothing new could still start being reported the day
//! after an unrelated commit landed — a report that moves on its own is a
//! report nobody can act on. Co-change is still computed, but only as
//! [`suggest`], which proposes candidates for a human to promote into the
//! ledger; nothing here writes the ledger.
//!
//! # What this crate is handed, and what it never opens
//!
//! Everything in here is a pure function of a [`Ledger`], a [`History`] and a
//! [`Settings`]. It opens no repository, reads no file and takes no path to
//! one: reading git is `codehelion-history`'s job, and keeping the two apart
//! is what lets the whole of this analysis be exercised against hand-built
//! histories rather than against a fixture whose commit ids have to be
//! regenerated whenever a test changes. [`look_up`] and [`guard`] go further and need no history at
//! all — they answer from the ledger alone, which is what makes them usable
//! before a change has been committed.
//!
//! # Determinism
//!
//! The point of this feature is to replace a judgement that moved between
//! readings with a number that does not, so every result here is required to
//! be byte-identical across runs over identical input. Three rules keep it
//! that way, and a change that breaks any of them breaks the feature rather
//! than merely a test:
//!
//! - **No hash-map iteration order reaches a result.** Counting is done in
//!   [`BTreeMap`]/[`BTreeSet`], and every returned sequence is either in
//!   ledger order, in history order, or explicitly sorted by a total order.
//! - **Every ordering used for output is total.** Sorting candidates by
//!   coupling alone would leave ties to the sort's input order; the comparison
//!   in [`suggest`] carries on through support and both unit names, which
//!   cannot tie.
//! - **The settings that produced a result travel with it.**
//!   [`Settings::digest`] is recorded in both [`Evaluation`] and
//!   [`Suggestion`], so two generations whose numbers differ can be told apart
//!   into "the code moved" and "the thresholds moved".
//!
//! # What it cannot see
//!
//! A change that correctly touches one member and has no business touching the
//! others is reported as an asymmetric change like any other, because nothing
//! in a path tells the two apart. That is why the counts are reported rather
//! than enforced by default, and why the answer to a noisy seam is to write
//! its members more narrowly rather than to add an exemption mechanism here.
//! Renames are read as a deletion and an addition — the history layer declines
//! to use similarity-based rename detection — so a moved file's co-change
//! history restarts at the move, while a glob-written ledger member follows a
//! directory that moves under it.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_history::{CommitId, CommitKind, CommitRecord, History, HistoryRange, RepoPath};
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

/// Commits after an asymmetric change that a later fix still counts as a
/// breach of it.
///
/// Counted in commits rather than in days so that the answer does not depend
/// on a clock, and so that a burst of work over one afternoon and the same
/// work spread over a month are read alike.
const DEFAULT_BREACH_WINDOW: usize = 20;

/// Paths a commit may touch before it stops counting towards co-change.
const DEFAULT_MAX_COMMIT_SIZE: usize = 30;

/// Coupling a unit pair needs before it is worth proposing.
const DEFAULT_MIN_COUPLING: f64 = 0.60;

/// Commits a unit pair needs to have shared before it is worth proposing.
const DEFAULT_MIN_SUPPORT: usize = 3;

/// Leading path components co-change is counted over.
///
/// Two: one crate directory, which is the granularity at which a pair of
/// parallel implementations of the same thing is visible. One component would
/// make every crate in `crates/` a single unit, and three would split a crate
/// into `src` and `tests` and count their relation instead.
const DEFAULT_SUGGEST_DEPTH: usize = 2;

/// How many decimal places a fraction is rendered with when it is hashed.
///
/// Fixed so that the digest describes the configured value rather than the way
/// the shortest-round-trip float formatter happened to spell it.
const DIGEST_FRACTION_PLACES: usize = 6;

/// Every threshold the analysis is allowed to be tuned by.
///
/// There is no default living anywhere else: a threshold that a caller may
/// leave unset is defaulted here, once, and the whole set is hashed into every
/// result. The fields are the `[seam-tracking]` table of `codehelion.toml`,
/// spelled the way that file spells its keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields, rename_all = "kebab-case")]
pub struct Settings {
    /// How many commits after an asymmetric change a `fix:` still breaches it.
    pub breach_window: usize,
    /// Ceiling on the commits read, newest first.
    ///
    /// Applied when the history is read, before anything here sees it. It is
    /// carried in this struct anyway so that the digest covers it: two runs
    /// whose counts differ because one read twice as much history have to be
    /// distinguishable from two runs whose counts differ because the code did.
    pub history_limit: usize,
    /// Paths a commit may touch before it is left out of co-change.
    ///
    /// A commit touching most of the tree hands support to every pair of paths
    /// in it, which is co-change in arithmetic and nothing in fact. The
    /// ceiling applies to [`suggest`] alone: an asymmetric change made by a
    /// sweeping commit is still an asymmetric change that happened, and
    /// [`evaluate`] counts it.
    pub max_commit_size: usize,
    /// Lowest coupling [`suggest`] will propose a pair at.
    pub min_coupling: f64,
    /// Fewest shared commits [`suggest`] will propose a pair at.
    pub min_support: usize,
    /// Leading path components [`suggest`] counts co-change over.
    pub suggest_depth: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            breach_window: DEFAULT_BREACH_WINDOW,
            history_limit: codehelion_history::DEFAULT_HISTORY_LIMIT,
            max_commit_size: DEFAULT_MAX_COMMIT_SIZE,
            min_coupling: DEFAULT_MIN_COUPLING,
            min_support: DEFAULT_MIN_SUPPORT,
            suggest_depth: DEFAULT_SUGGEST_DEPTH,
        }
    }
}

impl Settings {
    /// Reject values that would make a result meaningless.
    ///
    /// Every ceiling here has a floor of one rather than of zero, because zero
    /// does not disable the thing it bounds — it silently empties the result.
    /// A `breach-window` of zero would report that a repository has no
    /// breaches, a `min-support` of zero would propose every pair of units
    /// that ever shared a commit, and either would read as an answer.
    ///
    /// # Errors
    ///
    /// Returns [`SeamError::InvalidSetting`], naming the configuration key at
    /// fault, for the first field that is out of range.
    pub fn validate(&self) -> Result<(), SeamError> {
        for (key, value) in [
            ("breach-window", self.breach_window),
            ("history-limit", self.history_limit),
            ("max-commit-size", self.max_commit_size),
            ("min-support", self.min_support),
            ("suggest-depth", self.suggest_depth),
        ] {
            if value < 1 {
                return Err(SeamError::InvalidSetting(format!(
                    "seam-tracking.{key} must be at least 1"
                )));
            }
        }
        if !self.min_coupling.is_finite() || !(0.0..=1.0).contains(&self.min_coupling) {
            return Err(SeamError::InvalidSetting(format!(
                "seam-tracking.min-coupling must be a fraction from 0.0 to 1.0, not {}",
                self.min_coupling
            )));
        }
        Ok(())
    }

    /// A digest of the whole configuration, recorded beside every result.
    ///
    /// This is what tells "the numbers moved because the code changed" apart
    /// from "the numbers moved because the settings changed". Without it two
    /// generations of a report are two lists of counts with no way to know
    /// whether they were computed under the same rules, and a comparison
    /// between them means nothing.
    #[must_use]
    pub fn digest(&self) -> String {
        blake3::hash(self.canonical().as_bytes())
            .to_hex()
            .to_string()
    }

    /// The text the digest is taken over: one `key=value` line per field, in a
    /// fixed order, fractions at a fixed number of places.
    ///
    /// Destructured rather than read field by field so that adding a setting
    /// without deciding how it is rendered fails to compile. A setting missing
    /// from this rendering would be a setting two runs could differ by while
    /// claiming to have been computed alike.
    fn canonical(&self) -> String {
        let Self {
            breach_window,
            history_limit,
            max_commit_size,
            min_coupling,
            min_support,
            suggest_depth,
        } = self;
        let places = DIGEST_FRACTION_PLACES;
        format!(
            "seam-tracking.breach-window={breach_window}\n\
             seam-tracking.history-limit={history_limit}\n\
             seam-tracking.max-commit-size={max_commit_size}\n\
             seam-tracking.min-coupling={min_coupling:.places$}\n\
             seam-tracking.min-support={min_support}\n\
             seam-tracking.suggest-depth={suggest_depth}\n"
        )
    }
}

/// One `[[seam]]` entry: a name, the paths it binds together, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct SeamEntry {
    /// What the seam is called in a report, and what a later generation
    /// recognises it by.
    pub id: String,
    /// One glob per place the seam is implemented in, matched against
    /// repository-relative paths.
    ///
    /// The member is the unit of asymmetry: a change is asymmetric when it
    /// touched some of these and not the rest, so how narrowly they are
    /// written decides what the analysis can say. Two globs over one directory
    /// each answer "did this land on both sides"; one glob over both answers
    /// nothing.
    pub members: Vec<String>,
    /// What the seam is, in a sentence, for whoever reads the report.
    #[serde(default)]
    pub note: Option<String>,
}

/// The `[[seam]]` entries of one configuration, with their globs compiled.
///
/// Compiled once and held, because every member glob is matched against every
/// path of every commit in range: for a history at the default ceiling that is
/// the difference between compiling a handful of globs and compiling them tens
/// of thousands of times.
#[derive(Debug, Clone)]
pub struct Ledger {
    /// The entries, in the order the configuration wrote them.
    entries: Vec<SeamEntry>,
    /// One compiled matcher per member of each entry, in the same order.
    matchers: Vec<Vec<GlobMatcher>>,
}

/// Two ledgers are the same ledger when they were written the same way.
///
/// Implemented rather than derived because a compiled glob has no equality:
/// the matchers are a function of the entries, so comparing the entries
/// compares everything a ledger is.
impl PartialEq for Ledger {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for Ledger {}

impl Ledger {
    /// Validate and compile a set of entries.
    ///
    /// Every rejection here is a rule that would otherwise take effect
    /// silently and report nothing. A ledger that fails to load is visible;
    /// a seam that watches a glob matching no path, or a second entry
    /// overwriting a name a report already used, is not.
    ///
    /// # Errors
    ///
    /// Returns [`SeamError`] for a blank or duplicated `id`, for an entry with
    /// fewer than two members, for a blank member glob, or for a member glob
    /// that does not compile.
    pub fn new(entries: Vec<SeamEntry>) -> Result<Self, SeamError> {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut matchers = Vec::with_capacity(entries.len());
        for entry in &entries {
            if entry.id.trim().is_empty() {
                return Err(SeamError::EmptyId);
            }
            if !seen.insert(entry.id.as_str()) {
                return Err(SeamError::DuplicateId {
                    id: entry.id.clone(),
                });
            }
            if entry.members.len() < 2 {
                return Err(SeamError::TooFewMembers {
                    id: entry.id.clone(),
                    members: entry.members.len(),
                });
            }
            let mut compiled = Vec::with_capacity(entry.members.len());
            for member in &entry.members {
                if member.trim().is_empty() {
                    return Err(SeamError::EmptyMember {
                        id: entry.id.clone(),
                    });
                }
                // Built with globset's defaults, which is what `[suppression]`
                // does with the globs written next to these in the same file.
                // A pattern has to mean one thing per configuration file,
                // whichever section it was written in.
                let glob = Glob::new(member).map_err(|error| SeamError::BadGlob {
                    id: entry.id.clone(),
                    glob: member.clone(),
                    message: error.to_string(),
                })?;
                compiled.push(glob.compile_matcher());
            }
            matchers.push(compiled);
        }
        Ok(Self { entries, matchers })
    }

    /// Whether no seam has been written down.
    ///
    /// An empty ledger is a repository that has not named a seam yet, not an
    /// error: the observing commands work without one, and `guard` reports
    /// nothing rather than refusing to run.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries, in the order the configuration wrote them.
    #[must_use]
    pub fn entries(&self) -> &[SeamEntry] {
        &self.entries
    }

    /// The members of one seam that any of `paths` matches, ascending.
    ///
    /// A path may match more than one member of the same seam, and more than
    /// one seam; nothing here treats membership as exclusive.
    fn touched_members(&self, seam: usize, paths: &[RepoPath]) -> Vec<usize> {
        let Some(matchers) = self.matchers.get(seam) else {
            return Vec::new();
        };
        matchers
            .iter()
            .enumerate()
            .filter(|(_, matcher)| paths.iter().any(|path| matcher.is_match(path.as_str())))
            .map(|(index, _)| index)
            .collect()
    }
}

/// The `fix:` that landed on a member an asymmetric change had left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Breach {
    /// The fixing commit.
    pub commit: CommitId,
    /// Its subject line, so a report can name it in words.
    pub subject: String,
    /// How many commits after the asymmetric change it landed, at least one
    /// and at most the configured window.
    pub distance: usize,
    /// Which member of the seam it touched, as an index into the seam's
    /// members. When it touched several that had been left alone, the lowest.
    pub member: usize,
}

/// A commit that moved part of a seam and not the rest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsymmetricChange {
    /// The commit.
    pub commit: CommitId,
    /// When it was committed, seconds since the epoch.
    pub committer_time: i64,
    /// Its subject line.
    pub subject: String,
    /// Members it touched, as ascending indices into the seam's members.
    pub touched: Vec<usize>,
    /// Members it left alone, as ascending indices. Together with `touched`
    /// this is every member of the seam, and neither half is empty.
    pub untouched: Vec<usize>,
    /// The fix that later landed on one of the members left alone, if one did.
    pub breach: Option<Breach>,
}

/// What the history says about one seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamMetrics {
    /// The seam's id, as the ledger wrote it.
    pub id: String,
    /// Its member globs, as the ledger wrote them. Every index in `changes`
    /// is an index into this.
    pub members: Vec<String>,
    /// Its note, when the ledger carried one.
    pub note: Option<String>,
    /// How many commits in range moved part of it and not the rest.
    pub asymmetric_changes: usize,
    /// How many of those were followed by a fix to a member left alone.
    ///
    /// The ratio of this to `asymmetric_changes` is the number worth reading:
    /// asymmetry on its own may be nothing, and asymmetry that keeps calling a
    /// fix is a seam that costs something every time it is crossed.
    pub breaches: usize,
    /// The breaching commit of the most recent breached change, if any.
    pub last_breach: Option<CommitId>,
    /// Every asymmetric change, oldest first.
    pub changes: Vec<AsymmetricChange>,
}

/// What a ledger and a history say about each other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evaluation {
    /// Digest of the settings the counts were computed under.
    pub settings_digest: String,
    /// The commits they were computed over.
    pub range: HistoryRange,
    /// One entry per ledger seam, in ledger order, whether or not it has
    /// anything to report. A seam that produced nothing is a fact about the
    /// history, and dropping it would make an unchanged report look like a
    /// changed ledger.
    pub seams: Vec<SeamMetrics>,
}

/// Evaluate every seam in the ledger against the history.
///
/// Asymmetry is decided per commit and per seam: the members the commit
/// touched, against the members it did not. A breach is looked for in the
/// commits that follow, up to [`Settings::breach_window`] of them — the first
/// `fix:` among those that lands on a member this change left alone, and only
/// the first, because what is being counted is asymmetric changes that were
/// paid for rather than fixes that happened afterwards.
#[must_use]
pub fn evaluate(ledger: &Ledger, history: &History, settings: &Settings) -> Evaluation {
    let commits = history.commits();
    let seams = ledger
        .entries()
        .iter()
        .enumerate()
        .map(|(index, entry)| metrics(ledger, index, entry, commits, settings.breach_window))
        .collect();
    Evaluation {
        settings_digest: settings.digest(),
        range: history.range(),
        seams,
    }
}

/// Walk one seam over the whole history.
fn metrics(
    ledger: &Ledger,
    seam: usize,
    entry: &SeamEntry,
    commits: &[CommitRecord],
    breach_window: usize,
) -> SeamMetrics {
    // Membership is answered once per commit and reused by the breach scan,
    // which would otherwise re-match every glob against every commit inside
    // every window.
    let touched: Vec<Vec<usize>> = commits
        .iter()
        .map(|commit| ledger.touched_members(seam, &commit.paths))
        .collect();

    let mut changes: Vec<AsymmetricChange> = Vec::new();
    for (position, commit) in commits.iter().enumerate() {
        let here = touched.get(position).map_or(&[][..], Vec::as_slice);
        // Neither a commit that touched none of the members nor one that
        // touched all of them says anything about the seam holding together.
        if here.is_empty() || here.len() == entry.members.len() {
            continue;
        }
        let untouched: Vec<usize> = (0..entry.members.len())
            .filter(|member| !here.contains(member))
            .collect();
        let breach = first_breach(commits, &touched, position, &untouched, breach_window);
        changes.push(AsymmetricChange {
            commit: commit.id.clone(),
            committer_time: commit.committer_time,
            subject: commit.subject.clone(),
            touched: here.to_vec(),
            untouched,
            breach,
        });
    }

    let breaches = changes
        .iter()
        .filter(|change| change.breach.is_some())
        .count();
    let last_breach = changes
        .iter()
        .rev()
        .find_map(|change| change.breach.as_ref())
        .map(|breach| breach.commit.clone());
    SeamMetrics {
        id: entry.id.clone(),
        members: entry.members.clone(),
        note: entry.note.clone(),
        asymmetric_changes: changes.len(),
        breaches,
        last_breach,
        changes,
    }
}

/// The first fix inside the window that lands on a member left alone.
///
/// The window is counted in commits from the asymmetric change, so it is a
/// property of the history's shape rather than of anybody's clock, and the
/// sweeping-commit ceiling does not apply: a commit large enough to be useless
/// for co-change is still a commit that broke the seam.
fn first_breach(
    commits: &[CommitRecord],
    touched: &[Vec<usize>],
    position: usize,
    untouched: &[usize],
    breach_window: usize,
) -> Option<Breach> {
    commits
        .iter()
        .enumerate()
        .skip(position.saturating_add(1))
        .take(breach_window)
        .find_map(|(later, commit)| {
            if commit.kind != CommitKind::Fix {
                return None;
            }
            let landed = touched.get(later).map_or(&[][..], Vec::as_slice);
            // `untouched` is ascending, so the first match is the lowest
            // member index the fix reached.
            let member = untouched
                .iter()
                .copied()
                .find(|member| landed.contains(member))?;
            Some(Breach {
                commit: commit.id.clone(),
                subject: commit.subject.clone(),
                distance: later.saturating_sub(position),
                member,
            })
        })
}

/// A pair of directories the history keeps changing together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    /// The lower-sorting unit of the pair.
    pub left: String,
    /// The higher-sorting unit of the pair.
    pub right: String,
    /// Commits that touched both.
    pub support: usize,
    /// Of the commits that touched `left`, the fraction that also touched
    /// `right`.
    pub confidence_left_right: f64,
    /// Of the commits that touched `right`, the fraction that also touched
    /// `left`.
    pub confidence_right_left: f64,
    /// The lower of the two confidences.
    ///
    /// The minimum rather than either one alone, because a one-sided
    /// confidence is high for anything a busy directory drags along with it: a
    /// configuration file changed beside every crate has a confidence of one
    /// towards each of them and a coupling near zero, which is the honest
    /// answer.
    pub coupling: f64,
    /// Whether some one seam in the ledger already spans this pair.
    ///
    /// Reported rather than filtered out, because a pair the ledger already
    /// covers is evidence that the ledger is right, and a caller proposing new
    /// seams can drop it while a caller checking the ledger cannot recover it.
    pub in_ledger: bool,
}

/// Pairs of directories worth considering for the ledger.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    /// Digest of the settings the pairs were computed under.
    pub settings_digest: String,
    /// The commits they were computed over.
    pub range: HistoryRange,
    /// The pairs that cleared both floors, strongest first.
    pub candidates: Vec<Candidate>,
}

/// Propose unit pairs from co-change alone.
///
/// Nothing here consults the ledger to decide *what* to propose — the whole
/// point of the suggestion is to find what the ledger does not say — and
/// nothing here writes it. The ledger is read once, at the end, to mark the
/// pairs it already covers.
///
/// Co-change is counted over units of [`Settings::suggest_depth`] leading path
/// components rather than over files: two parallel implementations of one
/// thing rarely change the same file names, and the pair that matters is the
/// pair of directories. Commits above [`Settings::max_commit_size`] are
/// dropped before anything is counted.
#[must_use]
pub fn suggest(ledger: &Ledger, history: &History, settings: &Settings) -> Suggestion {
    let depth = settings.suggest_depth;
    let commits: Vec<&CommitRecord> = history
        .commits()
        .iter()
        .filter(|commit| !commit.is_sweeping(settings.max_commit_size))
        .collect();

    // Counting per unit and per unit pair. Ordered maps, not hashed ones: the
    // pair map is walked to build the result, and a hashed walk would order
    // the ties in it by whatever the hasher decided.
    let mut unit_commits: BTreeMap<String, usize> = BTreeMap::new();
    let mut pair_commits: BTreeMap<(String, String), usize> = BTreeMap::new();
    for commit in &commits {
        let units: BTreeSet<String> = commit
            .paths
            .iter()
            .map(|path| path.leading_components(depth).as_str().to_string())
            .filter(|unit| !unit.is_empty())
            .collect();
        for unit in &units {
            increment(&mut unit_commits, unit.clone());
        }
        for (index, left) in units.iter().enumerate() {
            for right in units.iter().skip(index.saturating_add(1)) {
                increment(&mut pair_commits, (left.clone(), right.clone()));
            }
        }
    }

    let covered = ledger_coverage(ledger, &commits, depth);
    let mut candidates: Vec<Candidate> = pair_commits
        .into_iter()
        .filter(|&(_, support)| support >= settings.min_support)
        .filter_map(|((left, right), support)| {
            let confidence_left_right = ratio(support, unit_commits.get(&left).copied());
            let confidence_right_left = ratio(support, unit_commits.get(&right).copied());
            let coupling = confidence_left_right.min(confidence_right_left);
            if coupling < settings.min_coupling {
                return None;
            }
            let in_ledger = spanned_by_one_seam(covered.get(&left), covered.get(&right));
            Some(Candidate {
                left,
                right,
                support,
                confidence_left_right,
                confidence_right_left,
                coupling,
                in_ledger,
            })
        })
        .collect();
    // Strongest first, and then by every remaining field until the order
    // cannot tie: two pairs with the same coupling and support still have
    // different names, so the sequence is decided by the data rather than by
    // the order the pairs were counted in.
    candidates.sort_by(|left, right| {
        right
            .coupling
            .total_cmp(&left.coupling)
            .then_with(|| right.support.cmp(&left.support))
            .then_with(|| left.left.cmp(&right.left))
            .then_with(|| left.right.cmp(&right.right))
    });

    Suggestion {
        settings_digest: settings.digest(),
        range: history.range(),
        candidates,
    }
}

/// Add one to `key`'s count.
fn increment<K: Ord>(counts: &mut BTreeMap<K, usize>, key: K) {
    let count = counts.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

/// `numerator / denominator` as a fraction, or zero when nothing was counted.
///
/// A unit named in a pair was necessarily counted, so the empty case is
/// unreachable; it is written as zero rather than as an assertion because a
/// confidence of zero is a candidate that fails every floor, which is the
/// answer a pair nobody observed deserves.
#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: usize, denominator: Option<usize>) -> f64 {
    match denominator {
        Some(denominator) if denominator > 0 => numerator as f64 / denominator as f64,
        _ => 0.0,
    }
}

/// Which `(seam, member)` pairs each unit's observed paths fall inside.
///
/// Built from the paths the counted commits actually named, never from paths
/// invented by expanding a glob: a glob covering a directory nobody has
/// touched says nothing about a pair drawn from commits.
fn ledger_coverage(
    ledger: &Ledger,
    commits: &[&CommitRecord],
    depth: usize,
) -> BTreeMap<String, BTreeSet<(usize, usize)>> {
    let mut covered: BTreeMap<String, BTreeSet<(usize, usize)>> = BTreeMap::new();
    if ledger.is_empty() {
        return covered;
    }
    // One path may appear in any number of commits, and matching it once is
    // enough.
    let paths: BTreeSet<&RepoPath> = commits.iter().flat_map(|commit| &commit.paths).collect();
    for path in paths {
        let unit = path.leading_components(depth).as_str().to_string();
        if unit.is_empty() {
            continue;
        }
        for (seam, matchers) in ledger.matchers.iter().enumerate() {
            for (member, matcher) in matchers.iter().enumerate() {
                if matcher.is_match(path.as_str()) {
                    covered
                        .entry(unit.clone())
                        .or_default()
                        .insert((seam, member));
                }
            }
        }
    }
    covered
}

/// Whether one seam holds both units, on two different members of itself.
///
/// Two different members: a seam is a statement that these places have to move
/// together, and two units inside one member glob are two places that member
/// says nothing about relative to each other.
fn spanned_by_one_seam(
    left: Option<&BTreeSet<(usize, usize)>>,
    right: Option<&BTreeSet<(usize, usize)>>,
) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };
    left.iter().any(|&(seam, member)| {
        right
            .iter()
            .any(|&(other_seam, other_member)| seam == other_seam && member != other_member)
    })
}

/// Where one path sits in one seam, and what sits opposite it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeamPlacement {
    /// The seam's id.
    pub seam: String,
    /// The member glob the path matched, as the ledger wrote it.
    pub member: String,
    /// The seam's other member globs: the places a change here may have to be
    /// carried to.
    pub other_members: Vec<String>,
}

/// One queried path and every seam it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLookup {
    /// The path as it was asked about.
    pub path: RepoPath,
    /// Its placements, in ledger order and then in member order. Empty when
    /// the path belongs to no seam — reported rather than omitted, so that
    /// asking about a path and getting a clear "nothing" is distinguishable
    /// from asking about nothing.
    pub seams: Vec<SeamPlacement>,
}

/// Answer which seams the given paths belong to, and what sits opposite them.
///
/// The ledger is the only thing consulted. No repository is opened, no file is
/// read and no revision is resolved, because the question this answers is
/// asked before the edit is made: given that I am about to change this file,
/// what else claims to implement the same thing?
#[must_use]
pub fn look_up(ledger: &Ledger, paths: &[RepoPath]) -> Vec<PathLookup> {
    paths
        .iter()
        .map(|path| PathLookup {
            path: path.clone(),
            seams: placements(ledger, path),
        })
        .collect()
}

/// Every placement one path has, in ledger order and then member order.
fn placements(ledger: &Ledger, path: &RepoPath) -> Vec<SeamPlacement> {
    let mut found = Vec::new();
    for (entry, matchers) in ledger.entries.iter().zip(&ledger.matchers) {
        for (index, matcher) in matchers.iter().enumerate() {
            if !matcher.is_match(path.as_str()) {
                continue;
            }
            let Some(member) = entry.members.get(index) else {
                continue;
            };
            found.push(SeamPlacement {
                seam: entry.id.clone(),
                member: member.clone(),
                other_members: entry
                    .members
                    .iter()
                    .enumerate()
                    .filter(|&(other, _)| other != index)
                    .map(|(_, glob)| glob.clone())
                    .collect(),
            });
        }
    }
    found
}

/// One seam a set of changed paths moved part of.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardVerdict {
    /// The seam's id.
    pub id: String,
    /// The member globs the change reached, as the ledger wrote them.
    pub touched: Vec<String>,
    /// The member globs it left alone.
    pub untouched: Vec<String>,
}

/// What a set of changed paths does to the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardReport {
    /// One verdict per seam the change moved part of, in ledger order.
    pub seams: Vec<GuardVerdict>,
}

impl GuardReport {
    /// Whether the change left every seam either whole or untouched.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.seams.is_empty()
    }
}

/// Report the seams a set of changed paths moved part of, and only part of.
///
/// A seam every one of whose members the change reached is not reported, and
/// neither is one it missed entirely: both are consistent, and a report listing
/// them would bury the one case worth reading. An empty ledger therefore
/// produces an empty report rather than an error — a repository that has not
/// named a seam has not broken one.
#[must_use]
pub fn guard(ledger: &Ledger, changed: &[RepoPath]) -> GuardReport {
    let seams = ledger
        .entries
        .iter()
        .zip(&ledger.matchers)
        .filter_map(|(entry, matchers)| {
            let mut touched = Vec::new();
            let mut untouched = Vec::new();
            for (member, matcher) in entry.members.iter().zip(matchers) {
                if changed.iter().any(|path| matcher.is_match(path.as_str())) {
                    touched.push(member.clone());
                } else {
                    untouched.push(member.clone());
                }
            }
            let asymmetric = !touched.is_empty() && !untouched.is_empty();
            asymmetric.then(|| GuardVerdict {
                id: entry.id.clone(),
                touched,
                untouched,
            })
        })
        .collect();
    GuardReport { seams }
}

/// Something a ledger or a `[seam-tracking]` setting got wrong.
///
/// Every variant names the configuration key at fault, because each of these
/// is a rule somebody wrote that would otherwise take no effect: a ledger that
/// loads and watches nothing reads exactly like a ledger that watches
/// something and finds nothing wrong.
#[derive(Debug, thiserror::Error)]
pub enum SeamError {
    /// A `[[seam]]` entry has no id.
    #[error("a [[seam]] entry has a blank id; every seam needs one to be reported under")]
    EmptyId,
    /// Two `[[seam]]` entries carry the same id.
    #[error(
        "two [[seam]] entries share the id {id:?}; a seam is compared with itself across generations by its id, so ids have to be distinct"
    )]
    DuplicateId {
        /// The id both entries carry.
        id: String,
    },
    /// A `[[seam]]` entry lists fewer than two members.
    #[error(
        "[[seam]] {id:?} lists {members} member glob(s); a seam needs at least two, because a seam of one has nothing to be asymmetric about"
    )]
    TooFewMembers {
        /// The entry's id.
        id: String,
        /// How many members it listed.
        members: usize,
    },
    /// A `[[seam]]` entry lists a blank member glob.
    #[error(
        "[[seam]] {id:?} lists a blank member glob; a blank glob matches nothing, so the seam would be watched with one side missing"
    )]
    EmptyMember {
        /// The entry's id.
        id: String,
    },
    /// A member glob does not compile.
    #[error("[[seam]] {id:?} member glob {glob:?} is malformed: {message}")]
    BadGlob {
        /// The entry's id.
        id: String,
        /// The glob as it was written.
        glob: String,
        /// What the glob parser said about it.
        message: String,
    },
    /// A `[seam-tracking]` setting is out of range.
    #[error("{0}")]
    InvalidSetting(String),
}
