//! Run-scoped report records: what the scan was, what it read, and what it
//! summed up.

use crate::report::{
    BaselineStatus, ExcludedCounts, FunnelStage, GroupCounts, RankingInfo, SuppressedCounts,
    UnparsedCounts, UnusedRule,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How long a run spent analysing and how long it spent recording.
///
/// Kept apart because they answer different questions: analysis time is what
/// a wider tree or a heavier mode costs, and recording time is what reuse
/// saves. A single elapsed time answers neither, and the two are far enough
/// apart in practice that guessing which dominates is guessing.
#[derive(Debug, Clone, Copy)]
pub struct RunTimings {
    /// Wall time from the start of discovery to the end of detection.
    pub analysis: std::time::Duration,
    /// Wall time spent writing the snapshot, when one was written.
    ///
    /// `None` when nothing was recorded, which is either a reused run — see
    /// [`RunInfo::reused`] — or a run whose recording failed.
    pub recording: Option<std::time::Duration>,
}

/// Metadata identifying one scan run.
#[derive(Debug, Serialize)]
pub struct RunInfo {
    /// Version of the tool that produced the report.
    pub tool_version: String,
    /// Analysis mode the scan ran in.
    pub mode: String,
    /// Absolute path of the scanned directory.
    pub root: String,
    /// Effective configuration that governed this run.
    pub configuration: ConfigurationInfo,
    /// RFC 3339 UTC start time.
    pub started_at: String,
    /// RFC 3339 UTC finish time.
    pub finished_at: String,
    /// The build variant the results belong to.
    pub build_variant: BuildVariantInfo,
    /// Versions of every detection component involved.
    pub detector_versions: Vec<DetectorVersion>,
    /// How the run composed its ranking.
    pub ranking: RankingInfo,
    /// Path of the local database the snapshot was recorded in.
    pub database: String,
    /// How long analysis took and how long recording took.
    ///
    /// Not serialized, and deliberately so: a duration is not reproducible, and
    /// `report --run` reconstructs a document from what was recorded rather
    /// than from what a clock said at the time. Publishing it would make a
    /// replay differ from the scan it replays in a field neither of them can
    /// do anything about, and would put a non-deterministic value in a schema
    /// whose other values are all derived from content.
    #[serde(skip)]
    pub timings: Option<RunTimings>,
    /// The `--db` a printed follow-up command has to repeat, when running one
    /// without it would open a different database.
    ///
    /// Not serialized: [`Self::database`] already publishes where the run was
    /// recorded, and a consumer reading JSON is not the one pasting a command
    /// back into a shell. This exists so that the commands the text report
    /// prints are commands that run — a report that names a next step the
    /// reader cannot take is worse than one that names none.
    #[serde(skip)]
    pub replay_database: Option<String>,
    /// Row id of the recorded scan run.
    ///
    /// Not a counter and not an ordering: a scan replaces the snapshot before
    /// it, so the database holds one run at a time. The id exists to name the
    /// recorded run to `report --run`, not to place it in a sequence.
    ///
    /// `None` means analysis completed but persistence did not. Such a report
    /// is intentionally not replayable: publishing a sentinel id would make
    /// an unrecorded run look like a real database row.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<i64>,
    /// Whether this invocation reused a matching completed local run.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reused: bool,
}

/// Effective configuration provenance recorded with a scan.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigurationInfo {
    /// How the configuration was selected: `defaults`, `root`, or `explicit`.
    pub source: String,
    /// Configuration file path when one supplied the settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Smallest clone the run could report, in tokens.
    pub min_clone_tokens: u32,
}

/// The build variant a scan's results belong to.
#[derive(Debug, Serialize)]
pub struct BuildVariantInfo {
    /// Analysis mode component of the variant.
    pub mode: String,
    /// Languages enabled for the run.
    pub languages: Vec<String>,
    /// The language bare `.h` headers were read as, absent when the run
    /// enumerated neither C nor C++.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,
    /// Normalization ruleset version.
    pub normalization_version: u32,
    /// Stable fingerprint of the variant.
    pub fingerprint: String,
    /// Compiler settings that define the variant, grouped first by the
    /// language whose build supplied them and then by stable setting name.
    ///
    /// Empty for Fast and Structural mode, which resolve no compiler build.
    /// An unresolved optional setting is absent rather than represented as an
    /// empty value, preserving the distinction recorded in the audit store.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

/// Version of one detection component.
///
/// Readable back as well as writable: a baseline records the versions its ids
/// were computed under, and a later run has to compare against them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectorVersion {
    /// Component name, such as `fp-schema` or `frontend.rust`.
    pub component: String,
    /// Its version identifier.
    pub version: String,
}

/// Aggregate counts over one scan.
#[derive(Debug, Serialize)]
pub struct Summary {
    /// Analysed-file counts by language.
    pub files: FileCounts,
    /// Total source lines across analysed files.
    pub lines: u64,
    /// Total tokens across analysed files.
    pub tokens: u64,
    /// Lexer diagnostics emitted while reading the sources.
    pub lexer_diagnostics: u64,
    /// How much of the source the parser could not follow, in the modes that
    /// parse. Absent in Fast mode, which lexes and does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unparsed: Option<UnparsedCounts>,
    /// Files the scan dropped, by cause.
    pub excluded: ExcludedCounts,
    /// What the baseline hid, when the scan was given one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<BaselineStatus>,
    /// File-tree delta from the preceding compatible completed run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changes: Option<TreeChanges>,
    /// What became of the highest-ranked groups of that same run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_churn: Option<TopChurn>,
    /// Clone-group counts by type.
    pub groups: GroupCounts,
    /// Suppressed-group counts by mechanism.
    pub suppressed: SuppressedCounts,
    /// Total serialized sibling entries, including entries hidden by a
    /// suppression rule. The text view keeps these out of the main listing
    /// unless requested, but the summary names the data that is there.
    pub siblings: u64,
    /// Total serialized near-miss entries, including entries hidden by a
    /// suppression rule.
    pub near_misses: u64,
    /// Measurements the selected mode deliberately did not produce.
    ///
    /// Fast mode compares token evidence only. Keeping the list in the
    /// summary makes that boundary visible to machine consumers without
    /// pretending that an empty list was measured as zero. Structural and
    /// Semantic reports serialize an empty list because the field is part of
    /// the stable summary shape in every mode.
    pub unmeasured_in_this_mode: Vec<String>,
    /// Configured suppression rules that hid nothing in this run.
    ///
    /// A rule that matches nothing reads as an instruction that took effect
    /// while the findings it was meant to cover are still being reported, so
    /// it is named rather than left to be discovered by accident.
    pub unused_suppressions: Vec<UnusedRule>,
    /// Configured suppression policies the selected mode could not apply.
    ///
    /// The Fast frontend compares tokens but does not classify boilerplate,
    /// test-only code, or integer-width families. Keeping these named makes a
    /// Fast result distinguishable from one where the policies were applied
    /// and matched nothing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unapplied_suppression_policies: Vec<String>,
    /// How many items each stage of the candidate pipeline passed on, in run
    /// order.
    ///
    /// A scan finds duplication by narrowing: everything the sources hold
    /// goes in and a few findings come out. Without the intermediate counts a
    /// run that found nothing looks the same as a run whose filters threw the
    /// evidence away. The stage vocabulary differs between the modes, and the
    /// structural run splits after candidate extraction into whole-unit
    /// verification and sub-unit run consolidation, so the list is a record of
    /// what happened rather than a single arithmetic chain.
    pub funnel: Vec<FunnelStage>,
    /// Groups of related units too large to refine as one piece, which were
    /// cut so grouping stays bounded.
    ///
    /// Every reported group is still cohesive; what the cut costs is the
    /// chance that two members on opposite sides of it would have been
    /// reported together.
    pub split_components: u64,
    /// Signature keys the sibling channel refused to index because too many
    /// units in the tree share them.
    ///
    /// A signature is evidence only while it is rare. On a tree where one
    /// signature covers most of a directory it proposes work without proposing
    /// duplication, so the channel leaves it out; saying how often that
    /// happened is what tells a reader the channel does not fit their code.
    pub common_signatures_skipped: u64,
    /// Units sharing the most widely shared signature the channel left out.
    ///
    /// Zero when nothing was left out. The maximum, not a total: it is the size
    /// of the largest excluded signature, which is what says whether the limit
    /// was met narrowly or by an order of magnitude.
    pub largest_skipped_signature_units: u64,
    /// Whether the candidate-pair budget ran out, making results
    /// potentially incomplete.
    pub pair_budget_exhausted: bool,
    /// Whether a resource ceiling truncated candidate search, so the result
    /// set may omit duplication that the scanned tree contains.
    pub search_truncated: bool,
    /// Stable identity records removed because an exact duplicate was emitted
    /// during final report assembly. Unequal payloads for one identity remain
    /// an invariant error instead of being collapsed.
    pub identity_collapsed: u64,
    /// The ceilings a run worked under when they were lowered on the command
    /// line rather than left where the configuration put them.
    ///
    /// A run told to distrust the tree reads less of it and reports fewer
    /// findings. Without this, that report and a report of a tree with less
    /// duplication in it are the same document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrails: Option<Guardrails>,
    /// What a compiler could supply about the tree, in the mode that asks one.
    ///
    /// Absent in the modes that ask nobody. Present and thin is a different
    /// report from absent: it says the run had a compiler and the compiler
    /// could not answer, which is why the findings look like the ones a
    /// syntactic run would produce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compiler: Option<CompilerCoverage>,
}

/// What became of the findings an earlier run put at the top.
///
/// A total measures how much duplication a tree holds, not how much work
/// has landed: closing eighteen groups out of nine thousand moves the total
/// by a rounding error. What did move is what happened to the groups that
/// were worth looking at, so that is stated separately.
#[derive(Debug, Clone, Serialize)]
pub struct TopChurn {
    /// Completed run used as the comparison point.
    pub since_run_id: i64,
    /// How many of each run's highest-ranked groups were compared.
    pub top: u64,
    /// Groups of that run's top that this run no longer holds, under this
    /// fingerprint or any successor that took over their history. A group
    /// whose history moved to a successor did not close.
    pub closed: Vec<String>,
    /// Groups of this run's top that the earlier run's top did not hold, and
    /// that did not inherit their history from one that it did.
    pub entered: Vec<String>,
    /// Groups of that run's top that this run's top still holds.
    ///
    /// Listed for the same reason the others are: the four ways an earlier
    /// top-ranked group can have ended up partition it exactly, so a reader
    /// can check any one number against the rest and the size of the top.
    /// Without that, a count of what left is a number with nothing to
    /// reconcile it against, and the arithmetic looks broken when it is not.
    pub still_ranked: Vec<String>,
    /// Groups of that run's top that this run still holds, below its top.
    ///
    /// Nothing happened to these but the ranking: their content is still
    /// duplicated, and other groups overtook them.
    pub outranked: Vec<String>,
    /// Groups of that run's top whose history a group of this run adopted.
    ///
    /// Kept out of [`Self::closed`] on purpose. Counting an adoption as a
    /// close would report one edit as both a fix and a fresh finding.
    pub superseded: Vec<String>,
    /// Groups of this run's top that inherited their history from a group of
    /// the earlier run's top, which is why they are not in [`Self::entered`].
    pub promoted: Vec<String>,
}

/// File-content changes since one compatible scan.
#[derive(Debug, Clone, Serialize)]
pub struct TreeChanges {
    /// Completed run used as the comparison point.
    pub since_run_id: i64,
    /// Paths present in both runs with changed contents.
    pub modified: u64,
    /// Paths absent from the earlier run.
    pub added: u64,
    /// Paths absent from this run.
    pub removed: u64,
    /// Paths present with identical contents in both runs.
    pub unchanged: u64,
}

/// What one recorded evaluation of the seam ledger found, and what moved since
/// the generation before it.
///
/// A seam is a set of paths implementing the same semantics in more than one
/// place. This is what `codehelion seam` recorded, read back rather than
/// recomputed: a report reads commits nowhere, and a count taken again here
/// would be a second derivation of a number the recorded run already settled.
#[derive(Debug, Clone, Serialize)]
pub struct SeamReport {
    /// Recorded seam run these counts come from.
    pub seam_run_id: i64,
    /// Digest of the settings that run was computed under.
    pub settings_digest: String,
    /// Oldest commit of the range it examined, when the range had one.
    pub first_commit: Option<String>,
    /// Newest commit of that range, when the range had one.
    pub last_commit: Option<String>,
    /// How many commits it examined.
    pub commits: u64,
    /// The seam run the deltas are taken against, when one exists under the
    /// same settings digest.
    pub since_seam_run_id: Option<i64>,
    /// The ledger's seams, in the order the recorded run wrote them.
    pub seams: Vec<ReportedSeam>,
}

/// One seam of the ledger as a recorded run measured it.
#[derive(Debug, Clone, Serialize)]
pub struct ReportedSeam {
    /// The ledger's name for this seam.
    pub id: String,
    /// What the ledger says the seam is, when it says anything.
    pub note: Option<String>,
    /// Commits that touched some of its members and not the rest.
    pub asymmetric_changes: u64,
    /// How many of those were followed by a fix to a member left alone.
    pub breaches: u64,
    /// The most recent breaching commit, when there was one.
    pub last_breach: Option<String>,
    /// Recorded findings whose location falls inside the seam.
    pub findings: u64,
    /// Change in [`Self::asymmetric_changes`] since the previous generation.
    ///
    /// Absent when the previous run did not carry this seam at all: a seam
    /// added to the ledger since then has no earlier generation, and a delta of
    /// its whole count would report the ledger's growth as the code's.
    pub asymmetric_changes_since: Option<i64>,
    /// Change in [`Self::breaches`] since the previous generation, on the same
    /// terms.
    pub breaches_since: Option<i64>,
    /// Change in [`Self::findings`] since the previous generation, on the same
    /// terms.
    pub findings_since: Option<i64>,
}

/// How much of the tree a compiler answered about.
#[derive(Debug, Serialize)]
pub struct CompilerCoverage {
    /// Files a compiler answered about.
    pub answered: u64,
    /// Files nobody was asked about: no helper here reads their language, or
    /// nothing said which unit they are compiled as.
    pub not_asked: u64,
    /// The same files [`Self::not_asked`] counts, by reason.
    ///
    /// Named for the same purpose [`Self::unavailable`] is: a bare count says
    /// a run was thin without saying what would thicken it, and a tree with no
    /// compilation database above it asks something different of its reader
    /// than a language no installed helper reads.
    pub not_asked_reasons: BTreeMap<String, u64>,
    /// Files a compiler was asked about and could not answer for, by reason.
    ///
    /// Kept apart from `not_asked` because the two call for different things:
    /// one is a project that needs something (a build script allowed to run, a
    /// compilation database), the other a helper nobody installed.
    pub unavailable: BTreeMap<String, u64>,
    /// Helper diagnostics grouped by their exact bounded text.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub diagnostics: BTreeMap<String, u64>,
    /// Execution classes that stopped a compiler from supplying an answer.
    ///
    /// Unlike [`Self::unavailable`], this keeps the precise permission and
    /// missing-information explanation that lets a reader decide whether to
    /// grant it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub execution_refusals: Vec<ExecutionRefusal>,
    /// How many times the helper had to be restarted along the way.
    ///
    /// Not a failure — a helper that dies on one file is expected, and the
    /// unit it died on is set aside rather than the run — but a run that
    /// restarted a compiler repeatedly read its tree through a process that
    /// kept losing its place, and that is worth seeing beside the counts.
    pub restarts: u32,
}

/// One execution permission that prevented compiler coverage.
#[derive(Debug, Serialize)]
pub struct ExecutionRefusal {
    /// Stable execution-class name.
    pub execution: String,
    /// Files this refusal left without a compiler answer.
    pub files: u64,
    /// Information unavailable without granting this class.
    pub cost: String,
    /// Exact command-line argument that grants only this class.
    pub permission_argument: String,
    /// Human-readable explanation assembled by the core policy.
    pub message: String,
}

/// The lowered ceilings a run worked under, and what asked for them.
///
/// A ceiling the selected mode's own stages never consult is absent rather
/// than filled in. Fast lexes and pairs; it runs no precise verification, no
/// component refinement, no near-match band and no sibling sweep, so stating
/// those numbers beside the ones it did enforce would describe a run that
/// never happened. Which ceilings a mode enforces is decided once, by
/// `enforced_ceilings` in the scan runtime, beside the mapping that hands each
/// stage its own ceiling.
#[derive(Debug, Serialize)]
pub struct Guardrails {
    /// The named profile that was asked for.
    pub profile: String,
    /// Largest file read, in bytes.
    pub max_file_bytes: u64,
    /// Per-file deterministic parse-work budget, expressed in compatibility
    /// milliseconds. Each millisecond admits 256 input bytes; files above the
    /// resulting byte budget are excluded and counted as skipped. Not a
    /// wall-clock deadline: host load and worker count do not change what a
    /// scan reports.
    pub parse_timeout_ms: u64,
    /// Longest a compiler helper may answer for one source unit, in milliseconds.
    pub helper_timeout_ms: u64,
    /// Longest posting list or fragment class admitted to pairing.
    pub posting_cap: usize,
    /// Largest number of candidate pairs any pairing pass examined.
    pub pair_budget: usize,
    /// Largest Structural pairs passed to precise verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_budget: Option<usize>,
    /// Largest dynamic-programming cell count for one Structural alignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_alignment_cells: Option<usize>,
    /// Width of the estimated-Jaccard diagnostic band below the candidate threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub near_miss_delta: Option<f64>,
    /// Maximum near-miss diagnostics retained by one run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub near_miss_cap: Option<usize>,
    /// Largest number of sibling-sweep comparisons.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sibling_candidate_budget: Option<usize>,
    /// Maximum siblings retained by one primary group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sibling_per_group_cap: Option<usize>,
    /// Maximum siblings retained by the whole run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sibling_total_cap: Option<usize>,
    /// Largest number of signature-sibling candidates compared in one run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_sibling_candidate_budget: Option<usize>,
    /// Maximum signature siblings retained by one primary group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_sibling_per_group_cap: Option<usize>,
    /// Maximum signature siblings retained by the whole run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_sibling_total_cap: Option<usize>,
    /// Largest number of units that may share a signature before that
    /// signature stops counting as sibling evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_sibling_max_units_per_signature: Option<usize>,
    /// Largest related unit component refined as one group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_component: Option<usize>,
}

/// Analysed-file counts by language.
#[derive(Debug, Serialize)]
pub struct FileCounts {
    /// All analysed files.
    pub total: u64,
    /// Rust files.
    pub rust: u64,
    /// C files.
    pub c: u64,
    /// C++ files.
    pub cpp: u64,
}
