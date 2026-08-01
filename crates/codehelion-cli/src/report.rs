//! Report model and its text and JSON views.
//!
//! One [`Report`] value carries everything a scan shows: the JSON reporter
//! serializes it verbatim and the text reporter renders the same value, so
//! the two views cannot drift apart. [`FindingDetail`] plays the same role
//! for `codehelion explain`.
//!
//! # Schema versioning
//!
//! JSON reports carry a top-level `schema_version` field, currently
//! [`SCHEMA_VERSION`]. The JSON Schema document shipped with this crate
//! ([`JSON_SCHEMA`], `schema/scan-report-v1.schema.json`) describes the
//! complete current format.
//!
//! [`sarif`] renders the same value as a SARIF 2.1.0 log for static-analysis
//! consumers.

pub mod sarif;

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::priority::{self, GroupFacts, Weights};
use codehelion_core::semantic::SemanticOperationGraph;
use codehelion_core::test_code::TestCodeEvidence;
use codehelion_store::artifact::MappingEvidence;
use codehelion_store::snapshot::{
    FunnelDropRow, FunnelStageRow, GuardrailsRow, SummaryRow, UnusedRuleRow,
};
use serde::{Deserialize, Serialize};

use crate::config::Suppression as SuppressionConfig;
use crate::suppress::VENDORED_SCOPE;

mod schema;

pub use schema::{
    BASELINE_COMPARE, BASELINE_SUPPRESS, FINDING_DETAIL_JSON_SCHEMA, FINDING_DETAIL_SCHEMA_URI,
    FINDING_DETAIL_SCHEMA_VERSION, GROUP_CONTINUING, GROUP_EXPANDED, GROUP_NEW, JSON_SCHEMA,
    SCHEMA_VERSION,
};
use schema::{
    EXPLAIN_RESPONSE_CLONE_GROUP, EXPLAIN_RESPONSE_CROSS_LANGUAGE_GROUP,
    EXPLAIN_RESPONSE_OCCURRENCE, GONE_LISTED, SCOPE_FRAGMENT, TEXT_GROUP_LIMIT, TEXT_MEMBER_LIMIT,
    detail_json,
};

/// A complete scan result: run metadata, summary counts and every group.
#[derive(Debug, Serialize)]
pub struct Report {
    /// JSON report format version.
    pub schema_version: u32,
    /// Metadata identifying the run that produced this report.
    pub run: RunInfo,
    /// Aggregate counts over the scan.
    pub summary: Summary,
    /// Every detected group, suppressed ones included, ordered by priority
    /// descending with the fingerprint bytes as a tie-break.
    pub groups: Vec<Group>,
}

/// An explicitly requested comparison across independent build variants.
///
/// This is intentionally outside [`Report`]: it does not aggregate ordinary
/// findings, coverage, savings, or baselines.
#[derive(Debug, Serialize)]
pub struct CrossVariantComparison {
    /// Comparison-domain schema and policy version.
    pub policy_version: String,
    /// Stable comparison-domain identity.
    pub comparison_id: String,
    /// What was actually compared, never a claim about all structural output.
    pub comparison_kind: String,
    /// Sorted fingerprints of every origin partition in scope.
    pub origin_variants: Vec<String>,
    /// Exact groups found directly across the origin variants.
    pub groups: Vec<CrossVariantGroup>,
}

/// An explicitly requested build-variant comparison that could not run.
///
/// This is deliberately distinct from an empty completed comparison: an
/// empty `groups` list means the requested domain was searched and contained
/// no exact clones, while this record says the comparison had fewer than two
/// independent partitions to search.
#[derive(Debug, Serialize)]
pub struct CrossVariantComparisonNotRun {
    /// Stable spelling for consumers that distinguish this from a completed
    /// comparison.
    pub status: String,
    /// The comparison operation that was requested.
    pub comparison_kind: String,
    /// Why the requested operation was not run.
    pub reason: String,
    /// Distinct normal scan partitions that were available to compare.
    pub origin_variants: Vec<String>,
}

/// One cross-build-variant group in an exported comparison.
#[derive(Debug, Serialize)]
pub struct CrossVariantGroup {
    /// Stable comparison-domain group id.
    pub id: String,
    /// Clone classification under the comparison policy.
    pub clone_type: String,
    /// Origin-aware members.
    pub members: Vec<CrossVariantMember>,
}

/// One origin-aware comparison member.
#[derive(Debug, Serialize)]
pub struct CrossVariantMember {
    /// Normal partition that produced this member.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// Source anchor relative to the scan root.
    pub file: String,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Best-effort unit name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Matched token count.
    pub token_count: usize,
}

/// An explicitly requested Rust-to-C++ semantic comparison.
///
/// It is deliberately outside [`Report`]: normal snapshots, savings,
/// baselines stay partition-local.
#[derive(Debug, Serialize)]
pub struct CrossLanguageComparison {
    /// Comparison-domain policy version.
    pub policy_version: String,
    /// Stable comparison-domain identity.
    pub comparison_id: String,
    /// What the comparison actually verified.
    pub comparison_kind: String,
    /// Sorted fingerprints of every origin partition in scope.
    pub origin_variants: Vec<String>,
    /// Candidate-selection accounting for this independent comparison.
    pub funnel: Vec<FunnelStage>,
    /// Whether a resource ceiling truncated this comparison's candidate
    /// search, so verified groups may be incomplete.
    pub search_truncated: bool,
    /// Verified Rust-to-C++ groups.
    pub groups: Vec<CrossLanguageGroup>,
}

/// One verified cross-language restricted-semantic group.
#[derive(Debug, Serialize)]
pub struct CrossLanguageGroup {
    /// Stable comparison-domain group identifier.
    pub id: String,
    /// Applied registered rule identifier.
    pub rule_id: String,
    /// Applied registered rule revision.
    pub rule_version: u32,
    /// Confidence, kept separate from ordinary clone confidence.
    pub semantic_confidence: f64,
    /// Closed API or compiler-construct correspondence identifiers used by the rule.
    pub correspondence_ids: Vec<String>,
    /// Origin-aware members and their normalised graphs.
    pub members: Vec<CrossLanguageMember>,
}

/// One member of a cross-language semantic group.
#[derive(Debug, Serialize)]
pub struct CrossLanguageMember {
    /// Fingerprint of the partition that produced this graph.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// File relative to the comparison root.
    pub file: String,
    /// 1-based start line.
    pub start_line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Best-effort unit name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Normalized graph that justified this member.
    pub graph: SemanticOperationGraph,
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
    /// Row id of the recorded scan run.
    ///
    /// Not a counter and not an ordering: a scan replaces the snapshot before
    /// it, so the database holds one run at a time. The id exists to name the
    /// recorded run to `report --run`, not to place it in a sequence.
    pub run_id: i64,
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
    /// Clone-group counts by type.
    pub groups: GroupCounts,
    /// Suppressed-group counts by mechanism.
    pub suppressed: SuppressedCounts,
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
    /// Whether the candidate-pair budget ran out, making results
    /// potentially incomplete.
    pub pair_budget_exhausted: bool,
    /// Whether a resource ceiling truncated candidate search, so the result
    /// set may omit duplication that the scanned tree contains.
    pub search_truncated: bool,
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

/// How much of the tree a compiler answered about.
#[derive(Debug, Serialize)]
pub struct CompilerCoverage {
    /// Files a compiler answered about.
    pub answered: u64,
    /// Files nobody was asked about: no helper here reads their language, or
    /// nothing said which unit they are compiled as.
    pub not_asked: u64,
    /// Files a compiler was asked about and could not answer for, by reason.
    ///
    /// Kept apart from `not_asked` because the two call for different things:
    /// one is a project that needs something (a build script allowed to run, a
    /// compilation database), the other a helper nobody installed.
    pub unavailable: BTreeMap<String, u64>,
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
#[derive(Debug, Serialize)]
pub struct Guardrails {
    /// The named profile that was asked for.
    pub profile: String,
    /// Largest file read, in bytes.
    pub max_file_bytes: u64,
    /// Longest one file was parsed for, in milliseconds.
    pub parse_timeout_ms: u64,
    /// Longest a compiler helper may answer for one source unit, in milliseconds.
    pub helper_timeout_ms: u64,
    /// Longest posting list or fragment class admitted to pairing.
    pub posting_cap: usize,
    /// Largest number of candidate pairs any pairing pass examined.
    pub pair_budget: usize,
    /// Largest related unit component refined as one group.
    pub max_component: usize,
}

mod ranking;

pub use ranking::{
    FunnelDrop, FunnelStage, Member, RankingInfo, Sort, Suppression, SuppressionKind, UnusedRule,
    compare_on, duplicated_tokens, is_search_truncation, order, ranked, restored, search_truncated,
    stored_funnel, stored_rules, unapplied_suppression_policies,
};

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

/// What a baseline did to this run's findings.
///
/// An entry that matched nothing is reported rather than left implicit, and
/// it is deliberately not phrased as a problem: a baseline going stale is a
/// duplication that got fixed. The number is what tells the reader that
/// `baseline update` has something to drop.
///
/// `mismatch` is the other case entirely — the baseline is intact but was
/// recorded under conditions that give every id a different value, so it
/// covers nothing at all. That is stated outright, because a suppression
/// silently covering nothing looks exactly like one that worked.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineStatus {
    /// The baseline file, as it was given on the command line.
    pub file: String,
    /// Entries the file holds.
    pub entries: u64,
    /// What the run was told to do with the entries: [`BASELINE_SUPPRESS`] to
    /// hide the findings they froze, [`BASELINE_COMPARE`] to hide nothing and
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
    /// Why the baseline does not describe this run, when it does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatch: Option<String>,
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
    /// Files over the configured size ceiling.
    pub too_large: u64,
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

/// Clone-group counts by type.
#[derive(Debug, Serialize)]
pub struct GroupCounts {
    /// All groups.
    pub total: u64,
    /// Verbatim (Type-1) groups.
    pub type_1: u64,
    /// Renamed (Type-2) groups.
    pub type_2: u64,
    /// Gapped (Type-3) groups. Always zero in modes that report no gapped
    /// clones.
    pub type_3: u64,
    /// Findings justified by registered semantic rules only. Always zero in
    /// modes that do not ask compiler helpers.
    pub restricted_semantic: u64,
    /// How many of the total describe a duplicated run inside units that are
    /// not clones of each other, rather than whole duplicated units. Always
    /// zero in modes that only compare whole units.
    pub fragment_scope: u64,
    /// Duplicated runs left out of the listing because a reported whole-unit
    /// group already covers them — the same duplication described twice.
    /// Reported so the fold is visible rather than silent.
    pub folded_runs: u64,
    /// Duplicated runs left out because a longer run covers every one of
    /// their occurrences and claims at least as much about them.
    pub subsumed_runs: u64,
    /// How many of the total live wholly in a test suite. Always zero in modes
    /// that cannot read the marker.
    pub test_code: u64,
}

/// Suppressed-group counts by mechanism.
#[derive(Debug, Serialize)]
pub struct SuppressedCounts {
    /// Groups the engine marked as noise.
    pub noise: u64,
    /// Groups hidden by a configured or inline suppression rule.
    pub by_rule: u64,
    /// Groups hidden because every occurrence sits in a vendored tree.
    ///
    /// Counted separately, and included in
    /// [`by_rule`](Self::by_rule), because this is the one rule that fires
    /// without anybody configuring it. A default nobody can see is a default
    /// nobody can disagree with.
    pub vendored: u64,
}

/// One clone group.
#[derive(Debug, Serialize)]
pub struct Group {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`, or
    /// `restricted-semantic`).
    pub clone_type: String,
    /// What each member is: `unit` for a whole duplicated unit, `fragment`
    /// for a run of statements duplicated inside units that need not be
    /// clones of each other.
    ///
    /// The two answer different questions about the same code, so a reader
    /// has to be able to tell them apart. They share one ranking because they
    /// compete for the same attention.
    pub scope: String,
    /// Statements each member covers, for fragment-scope groups; `None` for
    /// unit-scope groups, whose extent is the unit itself.
    pub statements: Option<u64>,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
    /// Shannon entropy, in bits, of the canonical occurrence's normalized
    /// token distribution. This remains evidence even when the normalized
    /// ratio marks the group as degenerate repetition.
    pub entropy_bits: f64,
    /// Ranking value with the inputs it was computed from.
    pub priority: Priority,
    /// Per-dimension similarity evidence, when the mode measured it; `None`
    /// in modes that match content exactly and score no dimensions.
    pub similarity: Option<Similarity>,
    /// Minimum raw-identifier Jaccard agreement against the canonical
    /// occurrence.
    ///
    /// For fragment-scope groups and split pairs, this is triage proxy evidence
    /// for whether a shared refactoring target may exist, not a similarity
    /// measure. It never affects clone detection, classification, or grouping;
    /// ranking may use it only as weak refactoring-difficulty evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_jaccard: Option<f64>,
    /// Material work shared by every member, when Structural mode measured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_materiality: Option<BodyMateriality>,
    /// The boilerplate shape shared by at least four fifths of members
    /// (`trivial-body`, `forwarding`, `macro-repetition`). Member-level
    /// classifications keep any exceptions visible; the configured category
    /// policy is stated either way.
    pub boilerplate: Option<String>,
    /// Whether every member is test code. A group spanning a suite and the
    /// code it exercises is not test code: that duplication crosses the
    /// boundary, which is the case worth reading.
    pub test_code: bool,
    /// Why every member is test code, when [`Self::test_code`] is true.
    ///
    /// `marker` wins when the group contains both marker- and path-derived
    /// members; `path` means every member was recognised from a configured
    /// test path. `null` means the group is not wholly test code.
    pub test_code_evidence: Option<TestCodeEvidence>,
    /// Whether the members differ from each other by one integer width and
    /// nothing else: one routine the type system made the author write once
    /// per width. Stated separately from `boilerplate` because it is a
    /// statement about how the members differ rather than about what any one
    /// of them does.
    pub width_family: bool,
    /// Whether this is a pair reported on its own because no group could hold
    /// both its members.
    ///
    /// A group asserts that every member is a copy of every other; being a
    /// copy is not transitive, so a unit can be a copy of two units that are
    /// not copies of each other, and only one of those relations fits in a
    /// group. Such a pair is reported as its own two-member finding, which
    /// means its members also appear elsewhere: these are the only findings
    /// that overlap.
    pub split_pair: bool,
    /// Why the group is hidden from default reports; `None` when visible.
    pub suppressed: Option<Suppression>,
    /// What the baseline the run was given says about this group; `None` when
    /// the run was given none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<GroupBaseline>,
    /// Registered-rule evidence for a restricted semantic finding. Absent for
    /// textual and structural clone classes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticEvidence>,
    /// Artifact-correlated refactoring estimates for this exact clone group.
    ///
    /// These are estimates, never a guarantee of a reduction. The list is
    /// empty until an artifact analysis has established a correlation for this
    /// recorded scan run.
    pub artifact_savings: Vec<ArtifactSavings>,
    /// Every occurrence, the canonical instance first.
    pub members: Vec<Member>,
}

/// One artifact-derived estimate attached to a clone group.
///
/// The source and artifact build variants remain explicit because matching
/// source text to a binary built under another configuration is evidence, not
/// identity. The amount is a model output and stays distinct from observed or
/// verified bytes.
#[derive(Debug, Clone, Serialize)]
pub struct ArtifactSavings {
    /// Stored artifact-analysis identifier that produced this estimate.
    pub artifact_analysis_id: i64,
    /// Fingerprint of the source build variant that named the clone group.
    pub source_build_variant_fingerprint: String,
    /// Fingerprint of the artifact build variant that supplied byte evidence.
    pub artifact_build_variant_fingerprint: String,
    /// Attributed duplicate bytes observed in the correlated artifact.
    pub duplicated_bytes: u64,
    /// Modelled refactoring savings in bytes; may be negative.
    pub estimated_refactor_savings_bytes: i64,
    /// Confidence that source and artifact identities were mapped correctly.
    pub mapping_confidence: String,
    /// Confidence that this source group is a clone.
    pub clone_confidence: f64,
    /// Confidence in the refactoring model itself.
    pub model_confidence: String,
    /// Combined confidence in the stated estimate.
    pub savings_confidence: String,
    /// Version of the model that produced the estimate.
    pub model_schema_version: String,
    /// Structured, model-specific assumptions retained with the estimate.
    pub assumptions: serde_json::Value,
}

/// Explainable evidence attached to a restricted semantic finding.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticEvidence {
    /// Version of the normalized operation-graph schema the rules read.
    pub schema_version: String,
    /// Every registered rule applied to establish this correspondence.
    pub rules: Vec<SemanticRuleEvidence>,
    /// The normalized operation graphs for the canonical and corresponding
    /// members, in that order.
    pub graphs: Vec<SemanticOperationGraph>,
    /// Graph-local node correspondences, in canonical source order.
    pub node_mappings: Vec<SemanticNodeMapping>,
}

/// One registered rule contributing to a semantic finding.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticRuleEvidence {
    /// Stable registry identifier.
    pub id: String,
    /// Rule semantics revision.
    pub version: u32,
    /// Semantic confidence after this rule's base confidence and available
    /// normalization coverage are combined.
    pub confidence: f64,
}

/// One explainable correspondence between graph-local operation positions.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SemanticNodeMapping {
    /// Zero-based position of the corresponding member in the semantic
    /// evidence's graph list. Zero is the canonical graph and is not a valid
    /// corresponding position.
    pub corresponding_member: u32,
    /// Node position in the canonical member graph.
    pub canonical: u32,
    /// Node position in the corresponding member graph.
    pub corresponding: u32,
}

/// A group's similarity evidence, one measured dimension per field.
///
/// Every dimension stays visible: the composite never replaces the
/// breakdown. An unavailable dimension is `None` — reported as absent, not
/// as a guessed number.
#[derive(Debug, Serialize)]
pub struct Similarity {
    /// The composite-weight recipe version the group was scored under.
    pub weight_version: String,
    /// Verbatim agreement of aligned statements' leading tokens.
    pub lexical: f64,
    /// Rename-invariant structural agreement.
    pub structural: f64,
    /// Control-flow-profile agreement, or `None` when neither member has
    /// control-flow operations to compare.
    pub control_flow: Option<f64>,
    /// Type agreement, or `None` when types are unavailable.
    pub type_similarity: Option<f64>,
    /// Call-name multiset agreement, or `None` when neither unit calls
    /// anything and there is nothing to compare.
    pub api: Option<f64>,
    /// Weighted mean of the measured dimensions.
    pub composite: f64,
    /// Weakest pairwise similarity inside the group: its cohesion.
    pub min_pairwise: f64,
    /// Confidence band of the classification (`high`, `medium`, `low`).
    ///
    /// A scan always reports one. It is `None` only when the evidence comes
    /// from a stored run recorded before the band was persisted: a band is a
    /// judgement, so an unrecorded one is reported as absent rather than
    /// re-derived from the numbers.
    pub confidence_band: Option<String>,
}

/// Conservative material-body evidence shared by every group member.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct BodyMateriality {
    /// Whether every member contains at least one loop.
    pub has_loop: bool,
    /// Whether every member calls a recognised allocation API.
    pub has_dynamic_allocation: bool,
    /// Fewest recovered call sites in any member.
    pub call_count: u64,
}

/// Where a group belongs in the report, as separated measures.
///
/// [`value`](Self::value) is what the report is ordered by, and it never
/// appears without the three measures it composes or the facts they were read
/// from. Everything here is on `0..1` and computed from the group alone, so
/// the same group ranks the same in every run it appears in.
#[derive(Debug, Clone, Serialize)]
pub struct Priority {
    /// The composed ranking value.
    pub value: f64,
    /// How sure the finding is duplication worth reporting.
    pub clone_confidence: f64,
    /// What keeping the copies in step costs.
    pub maintenance_risk: f64,
    /// What removing the duplication would cost.
    pub refactoring_difficulty: f64,
    /// How sure the finding is semantically equivalent. Absent until a
    /// compiler backend measures it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact. Absent until an
    /// artifact backend measures it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are. Absent: nothing measures savings
    /// yet, and a number here would read as a guarantee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub savings_confidence: Option<f64>,
    /// The facts the measures were read from.
    pub inputs: PriorityInputs,
}

/// What the ranking read about a group.
///
/// Reported in full so that a reader who disagrees with where a finding landed
/// can see which input put it there, and so that the ranking can be reproduced
/// from the published report rather than taken on trust.
#[derive(Debug, Clone, Serialize)]
pub struct PriorityInputs {
    /// Token count of the smallest occurrence, which is what decides how
    /// easily the group could have matched by coincidence.
    pub smallest_member_tokens: u64,
    /// Token count of the largest occurrence.
    pub largest_member_tokens: u64,
    /// Occurrences in the group.
    pub instances: u64,
    /// Minimum pairwise similarity across the group.
    pub similarity: f64,
    /// Distinct files the occurrences sit in.
    pub files: u64,
    /// Distinct directories the occurrences sit in.
    pub directories: u64,
    /// Distinct languages the occurrences are written in.
    pub languages: u64,
    /// The run's minimum clone length, which the sizes are read against.
    pub min_clone_tokens: u64,
    /// Minimum raw identifier-set Jaccard agreement against the canonical
    /// member, when Structural mode measured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_jaccard: Option<f64>,
    /// Weakest call-surface agreement, when Structural mode measured one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_similarity: Option<f64>,
    /// Whether every member contains a loop, when Structural mode measured it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_loop: Option<bool>,
    /// Whether every member calls a recognised allocation API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_dynamic_allocation: Option<bool>,
    /// Fewest call sites in any member, when Structural mode measured them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_count: Option<u64>,
    /// How often the duplicated code changed. Absent: no mode reads repository
    /// history yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub churn: Option<f64>,
    /// How many people own the copies. Absent, on the same footing as
    /// [`churn`](Self::churn).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ownership_spread: Option<f64>,
}

/// Rendering options for the text view of a [`Report`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TextOptions {
    /// List every group and every member instead of the summarised excerpt.
    pub verbose: bool,
    /// Emit ANSI colour codes.
    pub color: bool,
    /// Also list suppressed groups, with the reason each was hidden.
    pub show_suppressed: bool,
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

mod render;

use render::{Palette, render_group};

mod detail;

pub use detail::{
    CloneGroupDetail, CloneGroupSavingsDetail, CrossLanguageGroupDetail,
    CrossLanguageGroupMemberDetail, FindingDetail, GroupRef, RecordedInputs, RecordedPriority,
    SourceArtifactMappingDetail,
};

mod notes;

pub use notes::search_truncation_note;
use notes::{budget_note, depth_truncation_files, severed_note};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(super) mod tests;
