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

use std::collections::BTreeMap;
use std::io::{self, Write};

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::priority::{self, GroupFacts, Weights};
use codehelion_core::semantic::SemanticOperationGraph;
use codehelion_store::artifact::MappingEvidence;
use codehelion_store::snapshot::{FunnelDropRow, FunnelStageRow, SummaryRow, UnusedRuleRow};
use serde::{Deserialize, Serialize};

use crate::config::Suppression as SuppressionConfig;

/// Version of the JSON report format.
pub const SCHEMA_VERSION: u32 = 1;

/// The JSON Schema document describing [`Report`]'s JSON form.
pub const JSON_SCHEMA: &str = include_str!("../schema/scan-report-v1.schema.json");

/// [`Group::scope`] value of a group whose members are runs of statements.
const SCOPE_FRAGMENT: &str = "fragment";

/// Number of groups the default (non-verbose) text report lists.
const TEXT_GROUP_LIMIT: usize = 10;

/// Number of members per group the default text report lists.
const TEXT_MEMBER_LIMIT: usize = 5;

/// Number of gone baseline entries the text report lists before saying how
/// many it left out.
const GONE_LISTED: usize = 10;

/// [`BaselineStatus::mode`] value for hiding what the baseline froze.
pub const BASELINE_SUPPRESS: &str = "suppress";

/// [`BaselineStatus::mode`] value for hiding nothing and reporting each group
/// against the baseline instead.
pub const BASELINE_COMPARE: &str = "compare";

/// [`GroupBaseline::state`] value for a group the baseline froze.
pub const GROUP_CONTINUING: &str = "continuing";

/// [`GroupBaseline::state`] value for a group the baseline did not freeze.
pub const GROUP_NEW: &str = "new";

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
    /// How many times the helper had to be restarted along the way.
    ///
    /// Not a failure — a helper that dies on one file is expected, and the
    /// unit it died on is set aside rather than the run — but a run that
    /// restarted a compiler repeatedly read its tree through a process that
    /// kept losing its place, and that is worth seeing beside the counts.
    pub restarts: u32,
}

/// The lowered ceilings a run worked under, and what asked for them.
#[derive(Debug, Serialize)]
pub struct Guardrails {
    /// The named profile that was asked for.
    pub profile: &'static str,
    /// Largest file read, in bytes.
    pub max_file_bytes: u64,
    /// Longest one file was parsed for, in milliseconds.
    pub parse_timeout_ms: u64,
    /// Largest number of candidate pairs any pairing pass examined.
    pub pair_budget: usize,
}

/// One stage of the candidate pipeline.
#[derive(Debug, Serialize)]
pub struct FunnelStage {
    /// What the stage counts, as a short name.
    pub stage: String,
    /// Items the stage handed to the next one.
    pub passed: u64,
    /// Items the stage dropped, by cause. Causes that dropped nothing are
    /// left out.
    pub dropped: Vec<FunnelDrop>,
}

impl FunnelStage {
    /// A stage that passed `passed` items on and has yet to record any drop.
    #[must_use]
    pub fn new(stage: &str, passed: u64) -> Self {
        Self {
            stage: stage.to_string(),
            passed,
            dropped: Vec::new(),
        }
    }

    /// Record `count` items dropped for `cause`, ignoring a cause that
    /// dropped nothing.
    #[must_use]
    pub fn dropping(mut self, cause: &str, count: u64) -> Self {
        if count > 0 {
            self.dropped.push(FunnelDrop {
                cause: cause.to_string(),
                count,
            });
        }
        self
    }
}

/// Items one stage dropped for a single reason.
#[derive(Debug, Serialize)]
pub struct FunnelDrop {
    /// Why the items were dropped, as a `snake_case` cause.
    pub cause: String,
    /// How many were dropped.
    pub count: u64,
}

impl FunnelDrop {
    /// The cause as it reads in the text views.
    #[must_use]
    pub fn label(&self) -> String {
        self.cause.replace('_', " ")
    }
}

/// Put the entries in the order every view of a report shows them in.
///
/// Three keys, in this order: whether the configuration ranks the entry down,
/// then priority descending, then fingerprint ascending. The first is what
/// keeps boilerplate and test-suite repetition below the code under test
/// without changing what either of them scored; the last makes ties come out
/// the same on every machine.
///
/// One function rather than one per pipeline: the order is a property of the
/// report, and a scan that assembled its entries and a run rebuilt from the
/// database have to agree about it.
pub fn order(groups: &mut [Group], suppression: &SuppressionConfig) {
    let ranked_down = |group: &Group| {
        suppression.ranks_down(
            group
                .boilerplate
                .as_deref()
                .and_then(Boilerplate::from_name),
            group.test_code,
            group.width_family,
            group.split_pair,
        )
    };
    groups.sort_by(|a, b| {
        ranked_down(a)
            .cmp(&ranked_down(b))
            .then_with(|| b.priority.value.total_cmp(&a.priority.value))
            .then_with(|| a.fingerprint.cmp(&b.fingerprint))
    });
}

/// The run's funnel in the shape the audit database stores it.
#[must_use]
pub fn stored_funnel(funnel: &[FunnelStage]) -> Vec<FunnelStageRow> {
    funnel
        .iter()
        .map(|stage| FunnelStageRow {
            name: stage.stage.clone(),
            passed: stage.passed,
            dropped: stage
                .dropped
                .iter()
                .map(|drop| FunnelDropRow {
                    cause: drop.cause.clone(),
                    count: drop.count,
                })
                .collect(),
        })
        .collect()
}

/// The rules that hid nothing, in the shape the audit database stores them.
#[must_use]
pub fn stored_rules(rules: &[UnusedRule]) -> Vec<UnusedRuleRow> {
    rules
        .iter()
        .map(|rule| UnusedRuleRow {
            scope: rule.scope.clone(),
            pattern: rule.pattern.clone(),
        })
        .collect()
}

/// The summary a stored row and the groups it belongs to describe together.
///
/// Everything a group carries is counted off `groups` and everything else is
/// read from `stored`; nothing is held in both places. What a run measured
/// about its comparisons — the tree changes, the audit states, what a baseline
/// hid — is left absent here, because those are statements about *this*
/// invocation rather than about the recorded run.
#[must_use]
pub fn restored(files: FileCounts, stored: &SummaryRow, groups: &[Group]) -> Summary {
    let count = |predicate: &dyn Fn(&Group) -> bool| {
        u64::try_from(groups.iter().filter(|group| predicate(group)).count()).unwrap_or(u64::MAX)
    };
    let suppressed_as = |kind: SuppressionKind| {
        count(&|group| {
            group
                .suppressed
                .as_ref()
                .is_some_and(|suppression| suppression.kind == kind)
        })
    };
    Summary {
        files,
        lines: stored.lines,
        tokens: stored.tokens,
        lexer_diagnostics: stored.lexer_diagnostics,
        unparsed: stored
            .unparsed
            .map(|row| UnparsedCounts::from_counts(row.files, row.tokens, stored.tokens)),
        excluded: ExcludedCounts {
            generated: stored.excluded_generated,
            by_glob: stored.excluded_by_glob,
            skipped: stored.excluded_skipped,
        },
        baseline: None,
        // Not stored: the ceilings come from the invocation, and a recorded
        // run cannot say what the next one will be told to do.
        guardrails: None,
        // Nor this: what a compiler answered belongs to the run that asked
        // it, and this report is a recorded run read back.
        compiler: None,
        groups: GroupCounts {
            total: u64::try_from(groups.len()).unwrap_or(u64::MAX),
            type_1: count(&|group| group.clone_type == CloneClass::Type1.name()),
            type_2: count(&|group| group.clone_type == CloneClass::Type2.name()),
            type_3: count(&|group| group.clone_type == CloneClass::Type3.name()),
            restricted_semantic: count(&|group| {
                group.clone_type == CloneClass::RestrictedSemantic.name()
            }),
            fragment_scope: count(&|group| group.scope == CloneScope::Fragment.name()),
            folded_runs: stored.folded_runs,
            subsumed_runs: stored.subsumed_runs,
            test_code: count(&|group| group.test_code),
        },
        suppressed: SuppressedCounts {
            noise: suppressed_as(SuppressionKind::Noise),
            by_rule: suppressed_as(SuppressionKind::Rule),
        },
        unused_suppressions: stored
            .unused_suppressions
            .iter()
            .map(|rule| UnusedRule {
                scope: rule.scope.clone(),
                pattern: rule.pattern.clone(),
            })
            .collect(),
        funnel: stored
            .funnel
            .iter()
            .map(|stage| FunnelStage {
                stage: stage.name.clone(),
                passed: stage.passed,
                dropped: stage
                    .dropped
                    .iter()
                    .map(|drop| FunnelDrop {
                        cause: drop.cause.clone(),
                        count: drop.count,
                    })
                    .collect(),
            })
            .collect(),
        split_components: stored.split_components,
        pair_budget_exhausted: stored.pair_budget_exhausted,
    }
}

/// One configured suppression rule that matched nothing.
#[derive(Debug, Serialize)]
pub struct UnusedRule {
    /// Rule scope (`path_glob`, `symbol_pattern`, `stable_clone_id`).
    pub scope: String,
    /// The pattern as configured.
    pub pattern: String,
}

impl UnusedRule {
    /// One-line rendering for the text views, matching how a rule that *did*
    /// match is named.
    #[must_use]
    pub fn label(&self) -> String {
        match self.scope.as_str() {
            "path_glob" => format!("path glob {:?}", self.pattern),
            "symbol_pattern" => format!("symbol glob {:?}", self.pattern),
            "stable_clone_id" => format!("clone id {}", self.pattern),
            scope => format!("{scope} {:?}", self.pattern),
        }
    }
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
    /// Entries that hid a finding in this run.
    pub matched: u64,
    /// Entries that hid nothing, the duplication they covered being gone.
    pub stale: u64,
    /// Groups this run reports that the baseline never froze.
    pub appeared: u64,
    /// Tokens the stale entries repeated when they were frozen.
    pub stale_tokens: u64,
    /// Tokens the groups that appeared repeat now.
    ///
    /// Reported beside [`stale_tokens`](Self::stale_tokens) because a count of
    /// groups says nothing about size: removing one large duplication that
    /// leaves three small ones behind is progress that reads as a regression
    /// until both numbers are on the page.
    pub appeared_tokens: u64,
    /// Every stale entry, so that what was removed can be read rather than
    /// only counted.
    pub gone: Vec<GoneGroup>,
    /// Why the baseline does not describe this run, when it does not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mismatch: Option<String>,
    /// What the run does differently from the one the baseline was recorded
    /// against, where the difference leaves the entries matching but explains
    /// some of what went stale.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
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
    /// `continuing` when the baseline froze this group, `new` when it did not.
    pub state: String,
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
    /// Ranking value with the inputs it was computed from.
    pub priority: Priority,
    /// Per-dimension similarity evidence, when the mode measured it; `None`
    /// in modes that match content exactly and score no dimensions.
    pub similarity: Option<Similarity>,
    /// Minimum raw-identifier Jaccard agreement against the canonical member.
    ///
    /// This supports human triage only; it is not part of matching or priority.
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
    /// Whether every member is test code, recognised from the test marker in
    /// the source. A group spanning a suite and the code it exercises is not
    /// test code: that duplication crosses the boundary, which is the case
    /// worth reading.
    pub test_code: bool,
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
    /// Every occurrence, the canonical instance first.
    pub members: Vec<Member>,
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
    /// Control-flow-profile agreement.
    pub control_flow: f64,
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

/// How the run composed its ranking.
///
/// A run-level setting rather than a per-group one, and reported because two
/// reports ordered under different weights are different orderings of the same
/// findings, which nothing else in the document would say.
#[derive(Debug, Clone, Serialize)]
pub struct RankingInfo {
    /// Version of the ranking rules together with the weights applied.
    pub recipe: String,
    /// Weight given to what keeping the copies in step costs.
    pub maintenance_risk: u32,
    /// Weight given to how cheap the duplication would be to remove.
    pub refactoring_ease: u32,
}

impl Priority {
    /// The value a group carries between being built and being ranked.
    ///
    /// No report holds one: every group is handed straight to [`ranked`], which
    /// is also what the ranking has to read the group to do. Zero throughout,
    /// so a group that somehow escaped ranking sorts last rather than first.
    #[must_use]
    pub const fn unranked() -> Self {
        Self {
            value: 0.0,
            clone_confidence: 0.0,
            maintenance_risk: 0.0,
            refactoring_difficulty: 0.0,
            semantic_confidence: None,
            source_artifact_confidence: None,
            savings_confidence: None,
            inputs: PriorityInputs {
                smallest_member_tokens: 0,
                largest_member_tokens: 0,
                instances: 0,
                similarity: 0.0,
                files: 0,
                directories: 0,
                languages: 0,
                min_clone_tokens: 0,
                identifier_jaccard: None,
                api_similarity: None,
                has_loop: None,
                has_dynamic_allocation: None,
                call_count: None,
                churn: None,
                ownership_spread: None,
            },
        }
    }
}

impl Group {
    /// What the ranking reads about this group.
    ///
    /// Taken from the assembled report entry rather than from each mode's own
    /// data structures, so that Fast and Structural cannot rank the same facts
    /// differently, and so that anyone holding the JSON report can reproduce
    /// the ranking from it.
    ///
    /// `min_clone_tokens` is the run's length floor, which is a setting rather
    /// than a property of the group and so is not carried on it.
    fn facts(&self, min_clone_tokens: u64) -> GroupFacts {
        let tokens = || self.members.iter().map(|member| member.tokens);
        let distinct = |values: Vec<&str>| {
            let mut seen: Vec<&str> = values;
            seen.sort_unstable();
            seen.dedup();
            u64::try_from(seen.len()).unwrap_or(u64::MAX)
        };
        GroupFacts {
            clone_type: CloneClass::from_name(&self.clone_type).unwrap_or(CloneClass::Type3),
            scope: CloneScope::from_name(&self.scope).unwrap_or(CloneScope::Unit),
            instances: u64::try_from(self.members.len()).unwrap_or(u64::MAX),
            smallest_member_tokens: tokens().min().unwrap_or(0),
            largest_member_tokens: tokens().max().unwrap_or(0),
            min_pairwise: self.confidence,
            files: distinct(
                self.members
                    .iter()
                    .map(|member| member.file.as_str())
                    .collect(),
            ),
            directories: distinct(
                self.members
                    .iter()
                    .map(|member| directory_of(&member.file))
                    .collect(),
            ),
            languages: distinct(
                self.members
                    .iter()
                    .map(|member| member.language.as_str())
                    .collect(),
            ),
            min_clone_tokens,
            identifier_jaccard: self.identifier_jaccard,
            api_similarity: self
                .similarity
                .as_ref()
                .and_then(|similarity| similarity.api),
            has_loop: self.body_materiality.map(|body| body.has_loop),
            has_dynamic_allocation: self
                .body_materiality
                .map(|body| body.has_dynamic_allocation),
            call_count: self.body_materiality.map(|body| body.call_count),
            churn: None,
            ownership_spread: None,
        }
    }
}

/// The directory part of a report-relative path, `""` for a file at the root.
fn directory_of(path: &str) -> &str {
    path.rfind('/').map_or("", |cut| &path[..cut])
}

/// Rank one assembled group.
///
/// Every construction site hands its group through here, which is what keeps
/// one ranking rule over both analysis modes and all four kinds of entry.
#[must_use]
pub fn ranked(mut group: Group, weights: &Weights, min_clone_tokens: u64) -> Group {
    let facts = group.facts(min_clone_tokens);
    let ranked = priority::rank(&facts, weights);
    group.priority = Priority {
        value: ranked.final_priority,
        clone_confidence: ranked.clone_confidence,
        maintenance_risk: ranked.maintenance_risk,
        refactoring_difficulty: ranked.refactoring_difficulty,
        semantic_confidence: ranked.semantic_confidence,
        source_artifact_confidence: ranked.source_artifact_confidence,
        savings_confidence: ranked.savings_confidence,
        inputs: PriorityInputs {
            smallest_member_tokens: facts.smallest_member_tokens,
            largest_member_tokens: facts.largest_member_tokens,
            instances: facts.instances,
            similarity: facts.min_pairwise,
            files: facts.files,
            directories: facts.directories,
            languages: facts.languages,
            min_clone_tokens: facts.min_clone_tokens,
            identifier_jaccard: facts.identifier_jaccard,
            api_similarity: facts.api_similarity,
            has_loop: facts.has_loop,
            has_dynamic_allocation: facts.has_dynamic_allocation,
            call_count: facts.call_count,
            churn: facts.churn,
            ownership_spread: facts.ownership_spread,
        },
    };
    group
}

/// Which mechanism suppressed a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionKind {
    /// The engine marked the group as noise.
    Noise,
    /// A configured or inline suppression rule matched every member.
    Rule,
}

/// Why a group is hidden from default reports.
#[derive(Debug, Serialize)]
pub struct Suppression {
    /// The suppressing mechanism.
    pub kind: SuppressionKind,
    /// Engine noise category, present when `kind` is noise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Suppression-rule scope, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Suppression-rule pattern, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

impl Suppression {
    /// Human-readable label for the text views.
    #[must_use]
    pub fn label(&self) -> String {
        match self.kind {
            SuppressionKind::Noise => {
                format!("{} noise", self.reason.as_deref().unwrap_or("engine"))
            }
            SuppressionKind::Rule => {
                let pattern = self.pattern.as_deref().unwrap_or("");
                match self.scope.as_deref() {
                    Some("path_glob") => format!("path glob {pattern:?}"),
                    Some("symbol_pattern") => format!("symbol glob {pattern:?}"),
                    Some("stable_clone_id") => format!("clone id {pattern}"),
                    Some("inline_comment") => format!("{pattern} marker"),
                    Some("ast_pattern") => format!("boilerplate: {pattern}"),
                    Some("attribute") => format!("{pattern} attribute"),
                    Some(scope) => format!("{scope} {pattern:?}"),
                    None => "rule".to_string(),
                }
            }
        }
    }
}

impl Similarity {
    /// One-line rendering of the breakdown for the text views. An unavailable
    /// dimension prints as `n/a`, never as a number.
    #[must_use]
    pub fn line(&self) -> String {
        let type_similarity = self
            .type_similarity
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let api = self
            .api
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let band = self.confidence_band.as_deref().unwrap_or("n/a");
        format!(
            "similarity: composite {:.2} (lexical {:.2}, structural {:.2}, \
             control-flow {:.2}, type {type_similarity}, api {api}); \
             cohesion {:.2}; confidence {band} [{}]",
            self.composite,
            self.lexical,
            self.structural,
            self.control_flow,
            self.min_pairwise,
            self.weight_version,
        )
    }
}

/// One occurrence of a group's content.
#[derive(Debug, Serialize)]
pub struct Member {
    /// Stable per-occurrence finding identifier, hex-encoded.
    pub finding_id: String,
    /// Content fingerprint of the matched slice, hex-encoded.
    ///
    /// What makes an exported report comparable with a later run: the finding
    /// id is derived from the group fingerprint and moves whenever the group's
    /// content does, so a diff keyed on it can only see identity, never
    /// history.
    pub content: String,
    /// File path relative to the scan root.
    pub file: String,
    /// Language the occurrence was read as (`rust`, `c`, `cpp`).
    ///
    /// Which grammar read a file decides what the analysis could see in it,
    /// and a bare `.h` header is read as whichever of C and C++ the tree is
    /// written in. Recorded per occurrence so that a group spanning two
    /// languages is visible as one.
    pub language: String,
    /// 1-based first line.
    pub start_line: u32,
    /// 1-based last line.
    pub end_line: u32,
    /// Name of the enclosing unit, when anchored to one.
    ///
    /// `None` denotes a top-level fragment such as a file-scope initializer;
    /// it never means that the reporter failed to resolve an available unit.
    pub unit: Option<String>,
    /// Boilerplate shape of the enclosing whole unit, when Structural mode
    /// classified it. A missing value for a fragment means it has no whole
    /// body to classify; for a unit, no conservative shape fit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boilerplate: Option<String>,
    /// Size in tokens.
    pub tokens: u64,
    /// Whether this is the group's canonical instance.
    pub canonical: bool,
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
}

/// Minimal ANSI styling, disabled when the output is not a terminal.
struct Palette {
    enabled: bool,
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

    fn cyan(&self, text: &str) -> String {
        self.paint("36", text)
    }

    fn yellow(&self, text: &str) -> String {
        self.paint("33", text)
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
        self.render_summary(&palette, out)?;
        if opts.verbose {
            self.render_funnel(&palette, out)?;
        }
        self.render_groups(opts, &palette, out)
    }

    /// The stage-by-stage pass counts, wide enough to be read as a column.
    fn render_funnel(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        if self.summary.funnel.is_empty() {
            return Ok(());
        }
        let width = self
            .summary
            .funnel
            .iter()
            .map(|stage| stage.stage.len())
            .max()
            .unwrap_or(0);
        writeln!(out)?;
        writeln!(out, "{}", palette.bold("candidate pipeline:"))?;
        for stage in &self.summary.funnel {
            write!(out, "  {:width$}  {}", stage.stage, stage.passed)?;
            if !stage.dropped.is_empty() {
                let causes: Vec<String> = stage
                    .dropped
                    .iter()
                    .map(|drop| format!("{} {}", drop.label(), drop.count))
                    .collect();
                write!(out, "  (dropped: {})", causes.join(", "))?;
            }
            writeln!(out)?;
        }
        Ok(())
    }

    /// What the scan read: how much, what was left out, and what moved since
    /// the last time. Everything here is about the input, before a single
    /// group is mentioned.
    fn render_inputs(&self, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "  files: {} analysed (rust {}, c {}, cpp {})",
            summary.files.total, summary.files.rust, summary.files.c, summary.files.cpp,
        )?;
        // Which grammar read the bare `.h` headers decides what the analysis
        // could see in them, so a run that read any says so rather than
        // leaving the reader to infer it from the language counts.
        if summary.files.c + summary.files.cpp > 0
            && let Some(headers) = &self.run.build_variant.headers
        {
            writeln!(out, "    bare .h headers read as {headers}")?;
        }
        writeln!(
            out,
            "  excluded: {} generated, {} by glob, {} skipped",
            summary.excluded.generated, summary.excluded.by_glob, summary.excluded.skipped,
        )?;
        writeln!(
            out,
            "  lines: {}; tokens: {}; lexer diagnostics: {}",
            summary.lines, summary.tokens, summary.lexer_diagnostics,
        )?;
        // Before anything about what was found, because it is the sentence
        // that says how to read everything after it.
        if let Some(guardrails) = &summary.guardrails {
            writeln!(
                out,
                "  {} profile: files over {} bytes skipped, {} ms per file, {} candidate pairs per pass",
                guardrails.profile,
                guardrails.max_file_bytes,
                guardrails.parse_timeout_ms,
                guardrails.pair_budget,
            )?;
        }
        // Beside the ceilings, and for the same reason: it says how much of
        // what follows was decided by a compiler and how much was not.
        if let Some(compiler) = &summary.compiler {
            writeln!(
                out,
                "  compiler: answered for {} files, {} not asked, {} unanswered{}",
                compiler.answered,
                compiler.not_asked,
                compiler.unavailable.values().sum::<u64>(),
                if compiler.restarts == 0 {
                    String::new()
                } else {
                    format!(" (helper restarted {} time(s))", compiler.restarts)
                },
            )?;
            for (reason, count) in &compiler.unavailable {
                writeln!(out, "    {count} {reason}")?;
            }
        }
        if let Some(baseline) = &summary.baseline {
            writeln!(
                out,
                "  baseline {}: {} of {} entries matched, {} no longer found",
                baseline.file, baseline.matched, baseline.entries, baseline.stale,
            )?;
            // A baseline that covers nothing hides nothing, and that is
            // indistinguishable from a baseline that worked unless it is said.
            if let Some(reason) = &baseline.mismatch {
                writeln!(out, "    warning: this baseline hid nothing — {reason}")?;
            }
            // A stale count that a rule change explains reads as duplication
            // somebody fixed unless the other reading is offered.
            if let Some(caveat) = &baseline.caveat {
                writeln!(out, "    note: {caveat}")?;
            }
            // The same three numbers said as a before and an after, which is
            // the question somebody working duplication down is asking.
            writeln!(
                out,
                "    since it was recorded: {} gone (-{} repeated tokens), {} new (+{}), \
                 {} unchanged",
                baseline.stale,
                baseline.stale_tokens,
                baseline.appeared,
                baseline.appeared_tokens,
                baseline.matched,
            )?;
            render_gone(baseline, out)?;
        }
        Ok(())
    }

    fn render_summary(&self, palette: &Palette, out: &mut impl Write) -> io::Result<()> {
        let summary = &self.summary;
        writeln!(
            out,
            "{}",
            palette.bold(&format!("codehelion scan ({} mode)", self.run.mode))
        )?;
        writeln!(out, "  root: {}", self.run.root)?;
        self.render_inputs(out)?;
        // A recovering parser reports no failure, so the share it could not
        // follow is the only thing separating "little duplication here" from
        // "most of this was never read".
        if let Some(unparsed) = &summary.unparsed
            && unparsed.files > 0
        {
            writeln!(
                out,
                "    the parser could not follow {:.2}% of the tokens, over {} of {} files",
                unparsed.share * 100.0,
                unparsed.files,
                summary.files.total,
            )?;
        }
        writeln!(
            out,
            "  clone groups: {} (type-1 {}, type-2 {}, type-3 {}, restricted-semantic {}; suppressed: {} noise, {} by rule)",
            summary.groups.total,
            summary.groups.type_1,
            summary.groups.type_2,
            summary.groups.type_3,
            summary.groups.restricted_semantic,
            summary.suppressed.noise,
            summary.suppressed.by_rule,
        )?;
        let runs = &summary.groups;
        if runs.fragment_scope > 0 || runs.folded_runs > 0 || runs.subsumed_runs > 0 {
            writeln!(
                out,
                "    {} of them are runs duplicated inside units that are not clones of each \
                 other; {} more were folded into the groups that already cover them and {} \
                 into longer runs",
                runs.fragment_scope, runs.folded_runs, runs.subsumed_runs,
            )?;
        }
        if summary.groups.test_code > 0 {
            writeln!(
                out,
                "    {} of them are duplication inside test code, which repeats itself by \
                 design; a group spanning a test and what it exercises is not counted here",
                summary.groups.test_code,
            )?;
        }
        // The database keeps one scan, so printing a run number would advertise
        // a history that is not there. What a reader needs instead is where the
        // snapshot went and how to compare it with an earlier one.
        writeln!(
            out,
            "  snapshot: {} (one scan at a time; compare with an earlier scan through a baseline)",
            self.run.database
        )?;
        if !summary.unused_suppressions.is_empty() {
            let names: Vec<String> = summary
                .unused_suppressions
                .iter()
                .map(UnusedRule::label)
                .collect();
            writeln!(
                out,
                "  note: {} suppression rule(s) matched nothing: {}",
                summary.unused_suppressions.len(),
                names.join(", "),
            )?;
        }
        if summary.split_components > 0 {
            writeln!(
                out,
                "  note: {} set(s) of related units were too large to compare as one and were \
                 cut; clones of each other may be reported as separate groups{}",
                summary.split_components,
                severed_note(&summary.funnel),
            )?;
        }
        if summary.pair_budget_exhausted {
            writeln!(out, "{}", budget_note(&summary.funnel))?;
        }
        Ok(())
    }

    fn render_groups(
        &self,
        opts: TextOptions,
        palette: &Palette,
        out: &mut impl Write,
    ) -> io::Result<()> {
        let visible: Vec<&Group> = self
            .groups
            .iter()
            .filter(|group| group.suppressed.is_none())
            .collect();
        if !visible.is_empty() {
            let limit = if opts.verbose {
                visible.len()
            } else {
                TEXT_GROUP_LIMIT
            };
            writeln!(out)?;
            writeln!(out, "{}", palette.bold("top groups by priority:"))?;
            for group in visible.iter().take(limit) {
                render_group(group, opts, palette, out)?;
            }
            if visible.len() > limit {
                writeln!(out, "  ... and {} more groups", visible.len() - limit)?;
            }
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
                for group in &suppressed {
                    render_group(group, opts, palette, out)?;
                }
            }
        }
        Ok(())
    }
}

/// List what the baseline froze that this run no longer reports.
///
/// Only in compare mode: suppress mode is being asked to hide known
/// duplication, and a list of duplication that is no longer there is not what
/// it was asked for. The JSON report carries the list either way.
fn render_gone(baseline: &BaselineStatus, out: &mut impl Write) -> io::Result<()> {
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

/// Say where a group stands relative to the baseline the run was given.
///
/// Only groups the baseline did not freeze get a line. "Continuing" is the
/// unremarkable case and marking every one of them would bury the two that
/// matter; a group with a named predecessor is the case a reader would
/// otherwise misread as duplication they had just added.
fn render_group_baseline(group: &Group, out: &mut impl Write) -> io::Result<()> {
    let Some(baseline) = &group.baseline else {
        return Ok(());
    };
    if baseline.state != GROUP_NEW {
        return Ok(());
    }
    match &baseline.derived_from {
        Some(derived) => writeln!(
            out,
            "    new since the baseline, standing where {} stood ({} occurrence(s) in the \
             same place)",
            derived.group, derived.shared_sites,
        ),
        None => writeln!(out, "    new since the baseline"),
    }
}

/// Render one group: the priority with its inputs spelled out, then its
/// members. The non-verbose view truncates long member lists with an
/// explicit count, never silently.
fn render_group(
    group: &Group,
    opts: TextOptions,
    palette: &Palette,
    out: &mut impl Write,
) -> io::Result<()> {
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
    // A fragment-scope group states its extent: without it "type-1, 40
    // tokens" reads as a duplicated unit, which it is not.
    let scope = match (group.scope.as_str(), group.statements) {
        (SCOPE_FRAGMENT, Some(statements)) => format!(" run of {statements} statements"),
        (SCOPE_FRAGMENT, None) => " run".to_string(),
        _ => String::new(),
    };
    let priority = &group.priority;
    let spread = match (priority.inputs.files, priority.inputs.directories) {
        (0 | 1, _) => "within one file",
        (_, 0 | 1) => "within one directory",
        _ => "across directories",
    };
    writeln!(
        out,
        "  {} {}{scope} priority {:.2} [{spread}]{overlap}{marker}",
        palette.cyan(&group.fingerprint),
        group.clone_type,
        priority.value,
    )?;
    render_group_baseline(group, out)?;
    // The composed number is never shown on its own: the three measures that
    // made it say why the finding is where it is, and disagreeing with the
    // placement means disagreeing with one of them.
    let identifier_evidence = group.identifier_jaccard.map_or_else(String::new, |value| {
        format!(", raw identifiers {value:.2} Jaccard")
    });
    writeln!(
        out,
        "    confidence {:.2}, maintenance risk {:.2}, refactoring difficulty {:.2} \
         ({} instances, {}-{} tokens, {:.2} similarity{}, {} file(s))",
        priority.clone_confidence,
        priority.maintenance_risk,
        priority.refactoring_difficulty,
        priority.inputs.instances,
        priority.inputs.smallest_member_tokens,
        priority.inputs.largest_member_tokens,
        priority.inputs.similarity,
        identifier_evidence,
        priority.inputs.files,
    )?;
    if let Some(similarity) = &group.similarity {
        writeln!(out, "    {}", similarity.line())?;
    }
    if let Some(body) = group.body_materiality {
        writeln!(
            out,
            "    body evidence: loop {}, recognised allocation {}, at least {} call site(s)",
            if body.has_loop { "yes" } else { "no" },
            if body.has_dynamic_allocation {
                "yes"
            } else {
                "no"
            },
            body.call_count,
        )?;
    }
    let limit = if opts.verbose {
        group.members.len()
    } else {
        TEXT_MEMBER_LIMIT
    };
    for member in group.members.iter().take(limit) {
        let unit = member.unit.as_deref().map_or_else(
            || " [no enclosing unit]".to_string(),
            |name| format!(" ({name})"),
        );
        let canonical = if member.canonical { " [canonical]" } else { "" };
        writeln!(
            out,
            "    {}:{}-{}{unit}{canonical}",
            member.file, member.start_line, member.end_line,
        )?;
    }
    if group.members.len() > limit {
        writeln!(
            out,
            "    ... and {} more occurrences",
            group.members.len() - limit
        )?;
    }
    Ok(())
}

/// Where a stored run ranked a finding, as it was recorded.
///
/// Deliberately not [`Priority`]. That one is what a scan just computed, and
/// every measure in it exists by construction. This one is what a database
/// holds, which may have been written by a release that took fewer measures
/// than this one does — so a measure is `None` when the run did not take it,
/// rather than filled in with today's rules applied to yesterday's facts.
#[derive(Debug, Clone, Serialize)]
pub struct RecordedPriority {
    /// The composed ranking value the run acted on.
    pub value: f64,
    /// How sure the run was that the finding was worth reporting.
    pub clone_confidence: f64,
    /// What the run judged keeping the copies in step to cost.
    pub maintenance_risk: Option<f64>,
    /// What the run judged removing the duplication to cost.
    pub refactoring_difficulty: Option<f64>,
    /// How sure the finding is semantically equivalent.
    pub semantic_confidence: Option<f64>,
    /// How sure the source is the source of a given artifact.
    pub source_artifact_confidence: Option<f64>,
    /// How sure the reported savings are.
    pub savings_confidence: Option<f64>,
    /// The group facts behind the measures, as the stored run holds them.
    pub inputs: RecordedInputs,
}

/// The stored facts a recorded ranking was read from.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct RecordedInputs {
    /// Token count of the smallest occurrence.
    pub smallest_member_tokens: u64,
    /// Token count of the largest occurrence.
    pub largest_member_tokens: u64,
    /// Occurrences in the group.
    pub instances: u64,
    /// Distinct files the occurrences sit in.
    pub files: u64,
    /// Distinct directories the occurrences sit in.
    pub directories: u64,
    /// Distinct languages the occurrences are written in.
    pub languages: u64,
    /// The floor the run reported under. `None` for a run recorded before runs
    /// stored it, which is the one input a stored ranking can be missing while
    /// still having been computed from it.
    pub min_clone_tokens: Option<u64>,
}

/// The detail view of one occurrence, shared by `codehelion explain`'s text
/// and JSON output.
#[derive(Debug, Serialize)]
pub struct FindingDetail {
    /// The occurrence itself, in the same shape as a report member.
    #[serde(flatten)]
    pub member: Member,
    /// The owning group.
    pub group: GroupRef,
    /// Row id of the scan run the occurrence belongs to.
    pub scan_run: i64,
    /// Source/artifact mappings for this exact fragment occurrence.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_artifact_mappings: Vec<SourceArtifactMappingDetail>,
    /// Refactoring estimates retained for this finding's group.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub clone_group_savings: Vec<CloneGroupSavingsDetail>,
}

/// The standalone explain view of one explicitly requested Rust-to-C++
/// semantic comparison group.
#[derive(Debug, Serialize)]
pub struct CrossLanguageGroupDetail {
    /// Version of this detail document.
    pub schema_version: &'static str,
    /// Stable comparison-domain group identity.
    pub group_id: String,
    /// Stable identity of the comparison that recorded this group.
    pub comparison_id: String,
    /// Version of the comparison policy.
    pub policy_version: String,
    /// Root shared by the compared partitions.
    pub root_path: String,
    /// Origin build variants kept separate by the comparison.
    pub origin_variants: Vec<String>,
    /// Registered closed semantic rule that matched.
    pub rule_id: String,
    /// Registered rule revision.
    pub rule_version: u32,
    /// Confidence after the available semantic evidence was combined.
    pub semantic_confidence: f64,
    /// Closed API or compiler-construct correspondence identifiers used by the rule.
    pub correspondence_ids: Vec<String>,
    /// Origin-aware members and their normalized operation graphs.
    pub members: Vec<CrossLanguageGroupMemberDetail>,
}

/// One origin-aware member of a cross-language explain result.
#[derive(Debug, Serialize)]
pub struct CrossLanguageGroupMemberDetail {
    /// Origin build variant of this member's normal partition.
    pub origin_variant: String,
    /// Source language.
    pub language: String,
    /// Source location relative to the comparison root.
    pub file: String,
    /// One-based source range start.
    pub start_line: u32,
    /// One-based source range end.
    pub end_line: u32,
    /// Best-effort enclosing unit name.
    pub unit: Option<String>,
    /// Revalidated normalized operation graph.
    pub graph: SemanticOperationGraph,
}

/// One explicit source/artifact mapping shown by `explain`.
#[derive(Debug, Serialize)]
pub struct SourceArtifactMappingDetail {
    /// Standalone artifact analysis which supplied the correspondence.
    pub artifact_analysis_id: i64,
    /// Mapped artifact symbol identity.
    pub artifact_symbol_fingerprint: String,
    /// Source and artifact `BuildVariant` identities, never merged.
    pub source_build_variant_fingerprint: String,
    /// Artifact `BuildVariant` identity.
    pub artifact_build_variant_fingerprint: String,
    /// Derived mapping confidence label.
    pub confidence: String,
    /// Independent facts that justify the correspondence.
    pub evidence: MappingEvidence,
    /// Observed bytes attributed to this occurrence, when uniquely established.
    pub attributed_bytes: Option<u64>,
}

/// One persisted clone-group refactoring estimate shown by `explain`.
#[derive(Debug, Serialize)]
pub struct CloneGroupSavingsDetail {
    /// Artifact analysis which stored this estimate.
    pub artifact_analysis_id: i64,
    /// Source and artifact `BuildVariant` identities, never merged.
    pub source_build_variant_fingerprint: String,
    /// Artifact `BuildVariant` identity.
    pub artifact_build_variant_fingerprint: String,
    /// Fully attributed observed duplicate bytes.
    pub duplicated_bytes: u64,
    /// Estimated refactoring reduction; negative values remain visible.
    pub estimated_refactor_savings_bytes: i64,
    /// Mapping, source-clone, model, and estimate confidence remain separate.
    pub mapping_confidence: String,
    /// Source clone score.
    pub clone_confidence: f64,
    /// Confidence in the model assumptions.
    pub model_confidence: String,
    /// Confidence in this estimate.
    pub savings_confidence: String,
    /// Version of the structured assumptions model.
    pub model_schema_version: String,
    /// Structured model assumptions.
    pub assumptions: serde_json::Value,
}

/// A reference to an occurrence's owning group, carrying the evidence that
/// made it a finding rather than its identity alone.
#[derive(Debug, Serialize)]
pub struct GroupRef {
    /// Stable clone-group fingerprint, hex-encoded.
    pub fingerprint: String,
    /// Clone classification (`type-1`, `type-2`, `type-3`).
    pub clone_type: String,
    /// What each member is (`unit` or `fragment`), as recorded with the run.
    pub scope: String,
    /// Minimum pairwise similarity across the group.
    pub confidence: f64,
    /// Where the group was ranked, as recorded with the run, together with the
    /// facts it was ranked on. Absent for a group with no audited finding row.
    pub priority: Option<RecordedPriority>,
    /// Number of occurrences in the group, this one included.
    pub members: u64,
    /// The boilerplate shape every member matches, when they all match one.
    pub boilerplate: Option<String>,
    /// Whether every member of the group is test code, as recorded with the
    /// run.
    pub test_code: bool,
    /// Whether the group is a verified pair no larger group could hold, as
    /// recorded with the run.
    pub split_pair: bool,
    /// Per-dimension evidence, absent when the mode measured none (Fast).
    pub similarity: Option<Similarity>,
    /// Registered semantic evidence, when this is a restricted-semantic
    /// finding. `explain` retains the stored graphs rather than summarizing
    /// them into an opaque score.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub semantic: Option<SemanticEvidence>,
    /// The rule that suppressed the group in the recorded run, if one
    /// matched. A suppressed finding is still recorded and still explainable.
    pub suppressed: Option<Suppression>,
}

impl FindingDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
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
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "finding {}", self.member.finding_id)?;
        writeln!(
            out,
            "  location: {}:{}-{}",
            self.member.file, self.member.start_line, self.member.end_line,
        )?;
        if let Some(name) = &self.member.unit {
            writeln!(out, "  unit: {name}")?;
        }
        writeln!(out, "  tokens: {}", self.member.tokens)?;
        writeln!(
            out,
            "  canonical: {}",
            if self.member.canonical { "yes" } else { "no" }
        )?;
        // Which of the two the occurrence is decides how to read its span:
        // the whole unit is the clone, or a run inside it is.
        let scope = if self.group.scope == SCOPE_FRAGMENT {
            "duplicated run"
        } else {
            "duplicated unit"
        };
        writeln!(
            out,
            "  group: {} ({scope}, {}, score {:.2}, {} instances)",
            self.group.fingerprint,
            self.group.clone_type,
            self.group.confidence,
            self.group.members,
        )?;
        if let Some(similarity) = &self.group.similarity {
            writeln!(out, "    {}", similarity.line())?;
        }
        self.render_priority(out)?;
        if let Some(category) = &self.group.boilerplate {
            writeln!(out, "  boilerplate: {category}")?;
        }
        if self.group.split_pair {
            writeln!(
                out,
                "  pair: reported on its own, because no group holds both its members"
            )?;
        }
        if self.group.test_code {
            writeln!(out, "  test code: every occurrence is inside a test")?;
        }
        if let Some(cause) = &self.group.suppressed {
            writeln!(out, "  suppressed: {}", cause.label())?;
        }
        self.render_semantic_evidence(out)?;
        if !self.source_artifact_mappings.is_empty() {
            writeln!(out, "  source-artifact mappings:")?;
            for mapping in &self.source_artifact_mappings {
                writeln!(
                    out,
                    "    analysis {}: {} ({}) — {} bytes, {} facts, {} candidate(s){}",
                    mapping.artifact_analysis_id,
                    mapping.artifact_symbol_fingerprint,
                    mapping.confidence,
                    mapping
                        .attributed_bytes
                        .map_or_else(|| "unattributed".to_owned(), |bytes| bytes.to_string()),
                    mapping.evidence.facts.len(),
                    mapping.evidence.candidate_count,
                    if mapping.evidence.has_conflict {
                        "; conflicting evidence retained"
                    } else {
                        ""
                    },
                )?;
            }
        }
        if !self.clone_group_savings.is_empty() {
            writeln!(out, "  refactoring estimates (not guaranteed):")?;
            for savings in &self.clone_group_savings {
                writeln!(
                    out,
                    "    analysis {}: {} estimated bytes from {} attributed duplicate bytes; mapping {}, clone {:.3}, model {}, savings {}",
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
                    "      source build variant: {}",
                    savings.source_build_variant_fingerprint
                )?;
                writeln!(
                    out,
                    "      artifact build variant: {}",
                    savings.artifact_build_variant_fingerprint
                )?;
                writeln!(out, "      model schema: {}", savings.model_schema_version)?;
                writeln!(out, "      assumptions: {}", savings.assumptions)?;
            }
        }
        writeln!(out, "  scan run: {}", self.scan_run)?;
        Ok(())
    }

    /// Render the persisted graph evidence without collapsing it into a
    /// confidence score, so a reader can check the exact registered rule.
    fn render_semantic_evidence(&self, out: &mut impl Write) -> io::Result<()> {
        let Some(semantic) = &self.group.semantic else {
            return Ok(());
        };
        writeln!(out, "  semantic evidence: {}", semantic.schema_version)?;
        for rule in &semantic.rules {
            writeln!(
                out,
                "    rule {}@{} (confidence {:.2})",
                rule.id, rule.version, rule.confidence
            )?;
        }
        for (member, graph) in semantic.graphs.iter().enumerate() {
            let operations = graph
                .nodes
                .iter()
                .map(|node| node.kind.name())
                .collect::<Vec<_>>()
                .join(" -> ");
            writeln!(out, "    graph {}: {operations}", member + 1)?;
        }
        if !semantic.node_mappings.is_empty() {
            let mappings = semantic
                .node_mappings
                .iter()
                .map(|mapping| format!("{}→{}", mapping.canonical, mapping.corresponding))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(out, "    node mapping: {mappings}")?;
        }
        Ok(())
    }

    /// Why the finding is ranked where it is: each measure, the facts it read,
    /// and the rule that turned the one into the other.
    ///
    /// The rules are stated in words rather than as the arithmetic, because
    /// what a reader needs in order to argue with a placement is which fact
    /// drove it, not the constant it was multiplied by. The constants are in
    /// the ranking recipe the run recorded.
    fn render_priority(&self, out: &mut impl Write) -> io::Result<()> {
        let Some(priority) = &self.group.priority else {
            return Ok(());
        };
        let inputs = &priority.inputs;
        let measure = |value: Option<f64>| {
            value.map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"))
        };
        writeln!(out, "  priority: {:.2}", priority.value)?;
        writeln!(
            out,
            "    clone confidence {:.2} — {} tokens in the smallest occurrence{}, \
             {:.2} similarity, matched as {}",
            priority.clone_confidence,
            inputs.smallest_member_tokens,
            inputs.min_clone_tokens.map_or_else(
                // The floor decides how much a length is worth, so a run that
                // did not record it leaves the confidence readable but not
                // reproducible, and says which of the two this is.
                || " (the run did not record the length floor it used)".to_string(),
                |floor| format!(" against a {floor}-token floor"),
            ),
            self.group.confidence,
            self.group.clone_type,
        )?;
        writeln!(
            out,
            "    maintenance risk {} — {} occurrences over {} file(s) in {} \
             director(y/ies), largest {} tokens",
            measure(priority.maintenance_risk),
            inputs.instances,
            inputs.files,
            inputs.directories,
            inputs.largest_member_tokens,
        )?;
        writeln!(
            out,
            "    refactoring difficulty {} — {} tokens to move, {}, {} language(s)",
            measure(priority.refactoring_difficulty),
            inputs.largest_member_tokens,
            if self.group.scope == SCOPE_FRAGMENT {
                "a run inside its units, with no boundary to lift it out at"
            } else {
                "whole units, which already have a boundary"
            },
            inputs.languages,
        )?;
        // Named rather than left implicit: an input nobody has measured is not
        // an input worth zero, and a reader comparing two releases needs to
        // know which of the two it was.
        let reserved: Vec<&str> = [
            ("semantic confidence", priority.semantic_confidence),
            (
                "source-artifact confidence",
                priority.source_artifact_confidence,
            ),
            ("savings confidence", priority.savings_confidence),
        ]
        .into_iter()
        .filter(|(_, value)| value.is_none())
        .map(|(name, _)| name)
        .collect();
        if !reserved.is_empty() {
            writeln!(
                out,
                "    not measured by this run, and so not weighed: {}, churn, \
                 ownership spread",
                reserved.join(", "),
            )?;
        }
        Ok(())
    }
}

impl CrossLanguageGroupDetail {
    /// The detail as pretty-printed JSON, newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        Ok(text)
    }

    /// Render the closed correspondence and every origin-aware operation graph.
    ///
    /// # Errors
    ///
    /// Returns any error from the writer.
    pub fn render_text(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(out, "cross-language semantic group {}", self.group_id)?;
        writeln!(out, "  comparison: {}", self.comparison_id)?;
        writeln!(out, "  policy: {}", self.policy_version)?;
        writeln!(out, "  root: {}", self.root_path)?;
        writeln!(
            out,
            "  origin variants: {}",
            self.origin_variants.join(", ")
        )?;
        writeln!(
            out,
            "  rule: {}@{} (confidence {:.2})",
            self.rule_id, self.rule_version, self.semantic_confidence
        )?;
        writeln!(
            out,
            "  Correspondences: {}",
            self.correspondence_ids.join(", ")
        )?;
        for member in &self.members {
            writeln!(
                out,
                "  {} {}:{}-{} ({})",
                member.language,
                member.file,
                member.start_line,
                member.end_line,
                member.origin_variant,
            )?;
            if let Some(unit) = &member.unit {
                writeln!(out, "    unit: {unit}")?;
            }
            let operations = member
                .graph
                .nodes
                .iter()
                .map(|node| node.kind.name())
                .collect::<Vec<_>>()
                .join(" -> ");
            writeln!(
                out,
                "    graph {}: {operations}",
                member.graph.schema_version
            )?;
        }
        Ok(())
    }
}

/// What the exhausted candidate-pair ceiling cost, in the run's own numbers.
///
/// How much was skipped, not only that something was: a ceiling that trimmed
/// a hundred low-signal candidates and one that left nine tenths of the
/// corpus uncompared both read as "exhausted", and only one of them is a
/// result worth acting on.
///
/// The figure covers the stages the ceiling actually stopped. A pass that
/// finished its own search is not part of what was cut short, and counting it
/// in would dilute the share into saying less than it does.
fn budget_note(funnel: &[FunnelStage]) -> String {
    // Summed over whichever stages recorded the ceiling firing, rather than
    // over stage names written down here: each pass holds its own allowance,
    // and a list of names would let a pass added later go uncounted and read
    // as complete.
    let budgeted = funnel
        .iter()
        .filter(|stage| stage.dropped.iter().any(|drop| drop.cause == "pair_budget"));
    let (examined, skipped) = budgeted.fold((0u64, 0u64), |(examined, skipped), stage| {
        let dropped: u64 = stage
            .dropped
            .iter()
            .filter(|drop| drop.cause == "pair_budget")
            .map(|drop| drop.count)
            .sum();
        (
            examined.saturating_add(stage.passed),
            skipped.saturating_add(dropped),
        )
    });
    let total = examined.saturating_add(skipped);
    if total == 0 {
        return "  note: the candidate-pair budget was exhausted; results may be incomplete"
            .to_string();
    }
    format!(
        "  note: the candidate-pair budget stopped the search after {examined} of {total} \
         candidate pairs; the {skipped} left unexamined may hold duplication this report does \
         not list"
    )
}

/// What a cut kept from being reported, appended to the note about the cut.
///
/// Two units the cut put in different pieces were never weighed against each
/// other, so a relation between them is not carried out as a pair — it would
/// restate the same set once per crossing, and a set large enough to be cut is
/// large enough for that to be the whole report. The count says how much was
/// held back, which is the difference between a coarser answer and a quieter
/// one. Empty when nothing was held back, so the note stays one sentence in
/// the case where the cut cost nothing.
fn severed_note(funnel: &[FunnelStage]) -> String {
    let severed: u64 = funnel
        .iter()
        .flat_map(|stage| stage.dropped.iter())
        .filter(|drop| drop.cause == "the_ceiling_cut_the_set")
        .map(|drop| drop.count)
        .sum();
    if severed == 0 {
        return String::new();
    }
    format!(", and {severed} verified pair(s) across the cut are counted rather than listed")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(super) mod tests {
    use super::*;
    use boon::{Compiler, Schemas};
    use codehelion_core::discovery::Language;
    use codehelion_core::semantic::{
        OperationAttributes, OperationEdge, OperationEdgeKind, OperationKind, OperationNode,
        SemanticOperationGraph,
    };
    use codehelion_store::artifact::MappingEvidenceFact;

    pub(super) fn semantic_graph() -> SemanticOperationGraph {
        SemanticOperationGraph::new(
            Language::Rust,
            [1; 32],
            vec![
                OperationNode {
                    kind: OperationKind::Source,
                    attributes: OperationAttributes::default(),
                },
                OperationNode {
                    kind: OperationKind::Collect,
                    attributes: OperationAttributes::default(),
                },
            ],
            vec![OperationEdge {
                from: 0,
                to: 1,
                kind: OperationEdgeKind::Data,
            }],
        )
        .expect("test graph")
    }

    /// A two-group report whose second group is hidden by a path rule; shared
    /// with the sibling reporter tests.
    pub(super) fn sample_report() -> Report {
        Report {
            schema_version: SCHEMA_VERSION,
            run: RunInfo {
                tool_version: "0.1.0".to_string(),
                mode: "fast".to_string(),
                root: "/work/project".to_string(),
                started_at: "2026-01-01T00:00:00.000000Z".to_string(),
                finished_at: "2026-01-01T00:00:01.000000Z".to_string(),
                build_variant: BuildVariantInfo {
                    mode: "fast".to_string(),
                    languages: vec!["rust".to_string()],
                    headers: Some("c".to_string()),
                    normalization_version: 1,
                    fingerprint: "aa".repeat(32),
                },
                detector_versions: vec![DetectorVersion {
                    component: "fp-schema".to_string(),
                    version: "1".to_string(),
                }],
                ranking: RankingInfo {
                    recipe: Weights::default().recipe(),
                    maintenance_risk: 2,
                    refactoring_ease: 1,
                },
                database: ".codehelion/audit.db".to_string(),
                run_id: 1,
            },
            summary: Summary {
                files: FileCounts {
                    total: 2,
                    rust: 2,
                    c: 0,
                    cpp: 0,
                },
                lines: 40,
                tokens: 200,
                lexer_diagnostics: 0,
                unparsed: None,
                excluded: ExcludedCounts {
                    generated: 0,
                    by_glob: 0,
                    skipped: 0,
                },
                baseline: None,
                groups: GroupCounts {
                    total: 2,
                    type_1: 2,
                    type_2: 0,
                    type_3: 0,
                    restricted_semantic: 0,
                    fragment_scope: 0,
                    folded_runs: 0,
                    subsumed_runs: 0,
                    test_code: 0,
                },
                suppressed: SuppressedCounts {
                    noise: 0,
                    by_rule: 1,
                },
                unused_suppressions: Vec::new(),
                funnel: vec![
                    FunnelStage::new("tokens", 200),
                    FunnelStage::new("fingerprints", 64)
                        .dropping("high_frequency", 3)
                        .dropping("hash_collision", 0),
                    FunnelStage::new("verified pairs", 2),
                ],
                split_components: 0,
                pair_budget_exhausted: false,
                guardrails: None,
                compiler: None,
            },
            groups: vec![visible_group(), suppressed_group()],
        }
    }

    /// A plain visible group: the highest-priority entry of the sample report.
    fn visible_group() -> Group {
        ranked(
            Group {
                fingerprint: "0b".repeat(16),
                clone_type: "type-1".to_string(),
                scope: "unit".to_string(),
                statements: None,
                confidence: 1.0,
                priority: Priority::unranked(),
                similarity: None,
                identifier_jaccard: None,
                body_materiality: None,
                boilerplate: None,
                test_code: false,
                width_family: false,
                suppressed: None,
                baseline: None,
                split_pair: false,
                semantic: None,
                members: (0..7)
                    .map(|index| Member {
                        finding_id: format!("{index:032x}"),
                        content: "c0".repeat(16),
                        file: format!("src/file{index}.rs"),
                        language: "rust".to_string(),
                        start_line: 1,
                        end_line: 9,
                        unit: Some("checksum".to_string()),
                        boilerplate: None,
                        tokens: 80,
                        canonical: index == 0,
                    })
                    .collect(),
            },
            &Weights::default(),
            20,
        )
    }

    /// A group a path rule hid, kept in the report rather than dropped.
    fn suppressed_group() -> Group {
        ranked(
            Group {
                fingerprint: "0c".repeat(16),
                clone_type: "type-1".to_string(),
                scope: "unit".to_string(),
                statements: None,
                confidence: 1.0,
                priority: Priority::unranked(),
                similarity: None,
                identifier_jaccard: None,
                body_materiality: None,
                boilerplate: None,
                test_code: false,
                width_family: false,
                suppressed: Some(Suppression {
                    kind: SuppressionKind::Rule,
                    reason: None,
                    scope: Some("path_glob".to_string()),
                    pattern: Some("vendor/**".to_string()),
                }),
                baseline: None,
                split_pair: false,
                semantic: None,
                members: vec![
                    Member {
                        finding_id: "1".repeat(32),
                        content: "c0".repeat(16),
                        file: "vendor/a.rs".to_string(),
                        language: "rust".to_string(),
                        start_line: 1,
                        end_line: 5,
                        unit: None,
                        boilerplate: None,
                        tokens: 30,
                        canonical: true,
                    },
                    Member {
                        finding_id: "2".repeat(32),
                        content: "c0".repeat(16),
                        file: "vendor/b.rs".to_string(),
                        language: "rust".to_string(),
                        start_line: 1,
                        end_line: 5,
                        unit: None,
                        boilerplate: None,
                        tokens: 30,
                        canonical: false,
                    },
                ],
            },
            &Weights::default(),
            20,
        )
    }

    /// A gapped group as a mode that scores dimensions reports it: a
    /// similarity breakdown whose type dimension was never measured.
    pub(super) fn structural_group() -> Group {
        ranked(
            Group {
                fingerprint: "0d".repeat(16),
                clone_type: "type-3".to_string(),
                scope: "unit".to_string(),
                statements: None,
                confidence: 0.79,
                priority: Priority::unranked(),
                similarity: Some(Similarity {
                    weight_version: "structural-verify-v1".to_string(),
                    lexical: 0.71,
                    structural: 0.88,
                    control_flow: 0.90,
                    type_similarity: None,
                    api: Some(0.75),
                    composite: 0.82,
                    min_pairwise: 0.79,
                    confidence_band: Some("medium".to_string()),
                }),
                identifier_jaccard: Some(0.5),
                body_materiality: Some(BodyMateriality {
                    has_loop: true,
                    has_dynamic_allocation: false,
                    call_count: 3,
                }),
                boilerplate: None,
                test_code: false,
                width_family: false,
                suppressed: None,
                baseline: None,
                split_pair: false,
                semantic: None,
                members: vec![
                    Member {
                        finding_id: "3".repeat(32),
                        content: "c0".repeat(16),
                        file: "src/parse.rs".to_string(),
                        language: "rust".to_string(),
                        start_line: 10,
                        end_line: 30,
                        unit: Some("parse_header".to_string()),
                        boilerplate: None,
                        tokens: 60,
                        canonical: true,
                    },
                    Member {
                        finding_id: "4".repeat(32),
                        content: "c0".repeat(16),
                        file: "src/parse.rs".to_string(),
                        language: "rust".to_string(),
                        start_line: 40,
                        end_line: 62,
                        unit: Some("parse_trailer".to_string()),
                        boilerplate: None,
                        tokens: 58,
                        canonical: false,
                    },
                ],
            },
            &Weights::default(),
            20,
        )
    }

    /// A run duplicated inside two units that are not clones of each other:
    /// the members are stretches of their hosts, not the hosts.
    pub(super) fn fragment_group() -> Group {
        ranked(
            Group {
                fingerprint: "0e".repeat(16),
                clone_type: "type-1".to_string(),
                scope: SCOPE_FRAGMENT.to_string(),
                statements: Some(5),
                confidence: 1.0,
                priority: Priority::unranked(),
                similarity: None,
                identifier_jaccard: None,
                body_materiality: None,
                boilerplate: None,
                test_code: false,
                width_family: false,
                suppressed: None,
                baseline: None,
                split_pair: false,
                semantic: None,
                members: vec![
                    Member {
                        finding_id: "5".repeat(32),
                        content: "c0".repeat(16),
                        file: "src/render.rs".to_string(),
                        language: "rust".to_string(),
                        start_line: 17,
                        end_line: 21,
                        unit: Some("render_rows".to_string()),
                        boilerplate: None,
                        tokens: 39,
                        canonical: true,
                    },
                    Member {
                        finding_id: "6".repeat(32),
                        content: "c0".repeat(16),
                        file: "src/audit.rs".to_string(),
                        language: "rust".to_string(),
                        start_line: 11,
                        end_line: 15,
                        unit: Some("audit_entries".to_string()),
                        boilerplate: None,
                        tokens: 39,
                        canonical: false,
                    },
                ],
            },
            &Weights::default(),
            20,
        )
    }

    #[test]
    fn a_duplicated_run_states_its_extent_in_every_view() {
        let mut report = sample_report();
        report.summary.groups.total = 3;
        report.summary.groups.fragment_scope = 1;
        report.summary.groups.folded_runs = 4;
        report.summary.groups.subsumed_runs = 2;
        report.groups.insert(0, fragment_group());

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        let group = &value["groups"][0];
        assert_eq!(group["scope"], "fragment");
        assert_eq!(group["statements"], 5);
        // A whole-unit group says so, and says it has no such extent.
        assert_eq!(value["groups"][1]["scope"], "unit");
        assert_eq!(value["groups"][1]["statements"], serde_json::Value::Null);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("type-1 run of 5 statements priority 0."));
        // What was folded away is stated rather than silently dropped.
        assert!(text.contains(
            "1 of them are runs duplicated inside units that are not clones of each other; \
             4 more were folded into the groups that already cover them and 2 into longer runs"
        ));
    }

    #[test]
    fn a_rule_that_matched_nothing_is_named_not_left_to_be_noticed() {
        let mut report = sample_report();
        report.summary.unused_suppressions = vec![
            UnusedRule {
                scope: "path_glob".to_string(),
                pattern: "third_party/**".to_string(),
            },
            UnusedRule {
                scope: "stable_clone_id".to_string(),
                pattern: "abcd1234".to_string(),
            },
        ];

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(
            value["summary"]["unused_suppressions"][0]["scope"],
            "path_glob"
        );
        assert_eq!(
            value["summary"]["unused_suppressions"][1]["pattern"],
            "abcd1234"
        );

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        // Named the way a rule that did match is named, so the two read alike.
        assert!(text.contains(
            "note: 2 suppression rule(s) matched nothing: path glob \"third_party/**\", \
             clone id abcd1234"
        ));
    }

    #[test]
    fn a_run_with_every_rule_matching_says_nothing_about_them() {
        let mut buffer = Vec::new();
        sample_report()
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        assert!(
            !String::from_utf8(buffer)
                .unwrap()
                .contains("matched nothing")
        );
    }

    #[test]
    fn a_group_inside_the_suite_says_so_in_every_view() {
        let mut report = sample_report();
        report.summary.groups.test_code = 1;
        let mut group = fragment_group();
        group.test_code = true;
        report.groups.insert(0, group);

        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(value["groups"][0]["test_code"], true);
        // A group reaching outside the suite is the interesting case, and says
        // as much rather than leaving the field out.
        assert_eq!(value["groups"][1]["test_code"], false);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        // Shown, not hidden, and its place in the ranking is explained.
        assert!(text.contains("[test code]"));
        assert!(text.contains("1 of them are duplication inside test code"));
    }

    #[test]
    fn an_occurrence_inside_the_suite_explains_why() {
        let mut group = fragment_group();
        group.test_code = true;
        let detail = FindingDetail {
            member: group.members.remove(0),
            group: GroupRef {
                fingerprint: "0e".repeat(16),
                clone_type: "type-1".to_string(),
                scope: SCOPE_FRAGMENT.to_string(),
                confidence: 1.0,
                priority: None,
                members: 2,
                boilerplate: None,
                test_code: true,
                split_pair: false,
                similarity: None,
                semantic: None,
                suppressed: None,
            },
            scan_run: 3,
            source_artifact_mappings: Vec::new(),
            clone_group_savings: Vec::new(),
        };
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        assert!(
            String::from_utf8(buffer)
                .unwrap()
                .contains("test code: every occurrence is inside a test")
        );
    }

    #[test]
    fn an_occurrence_of_a_run_explains_itself_as_a_run() {
        let mut detail = FindingDetail {
            member: fragment_group().members.remove(0),
            group: GroupRef {
                fingerprint: "0e".repeat(16),
                clone_type: "type-1".to_string(),
                scope: SCOPE_FRAGMENT.to_string(),
                confidence: 1.0,
                priority: None,
                members: 2,
                boilerplate: None,
                test_code: false,
                split_pair: false,
                similarity: None,
                semantic: None,
                suppressed: None,
            },
            scan_run: 3,
            source_artifact_mappings: Vec::new(),
            clone_group_savings: Vec::new(),
        };
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("duplicated run, type-1"));

        // The same occurrence in a whole-unit group reads the other way.
        detail.group.scope = "unit".to_string();
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        assert!(
            String::from_utf8(buffer)
                .unwrap()
                .contains("duplicated unit")
        );
    }

    #[test]
    fn the_unparsed_share_counts_files_and_tokens_against_the_whole_scan() {
        let counts = UnparsedCounts::new([0, 250, 0, 750], 4000);
        assert_eq!(counts.files, 2, "only the files that lost something count");
        assert_eq!(counts.tokens, 1000);
        assert!((counts.share - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn a_scan_the_parser_followed_reports_a_share_of_nothing() {
        let clean = UnparsedCounts::new([0, 0], 4000);
        assert_eq!((clean.files, clean.tokens), (0, 0));
        assert!(clean.share.abs() < f64::EPSILON);
        // An empty scan divides by nothing rather than producing a NaN that
        // would serialize as `null` and read as "not measured".
        let empty = UnparsedCounts::new([], 0);
        assert!(empty.share.abs() < f64::EPSILON);
    }

    #[test]
    fn a_lexing_mode_reports_no_parse_coverage_rather_than_a_clean_one() {
        // Fast mode has no parser, so `unparsed` is absent from its JSON. A
        // zero there would claim the parser followed everything.
        let value: serde_json::Value =
            serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
        assert!(value["summary"].get("unparsed").is_none());
    }

    #[test]
    fn json_view_serializes_the_documented_shape() {
        let value: serde_json::Value =
            serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["run"]["mode"], "fast");
        assert_eq!(value["run"]["build_variant"]["normalization_version"], 1);
        assert_eq!(value["summary"]["files"]["total"], 2);
        assert_eq!(value["summary"]["pair_budget_exhausted"], false);
        let group = &value["groups"][0];
        assert_eq!(group["clone_type"], "type-1");
        assert_eq!(group["priority"]["inputs"]["largest_member_tokens"], 80);
        assert_eq!(group["width_family"], false);
        assert_eq!(group["suppressed"], serde_json::Value::Null);
        assert_eq!(group["members"][0]["canonical"], true);
        let suppressed = &value["groups"][1]["suppressed"];
        assert_eq!(suppressed["kind"], "rule");
        assert_eq!(suppressed["scope"], "path_glob");
        assert!(suppressed.get("reason").is_none());
    }

    #[test]
    fn current_json_report_validates_against_the_shipped_v1_schema() {
        let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
        let mut schemas = Schemas::new();
        let mut compiler = Compiler::new();
        let uri = "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/scan-report-v1.schema.json";
        compiler.add_resource(uri, schema).unwrap();
        let index = compiler.compile(uri, &mut schemas).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&sample_report().to_json().unwrap()).unwrap();
        schemas.validate(&value, index).unwrap();
    }

    #[test]
    fn restricted_semantic_evidence_is_explicit_in_json() {
        let mut report = sample_report();
        let group = &mut report.groups[0];
        group.clone_type = "restricted-semantic".to_string();
        group.semantic = Some(SemanticEvidence {
            schema_version: "sog-v1".to_string(),
            rules: vec![SemanticRuleEvidence {
                id: "sequence-pipeline-v1".to_string(),
                version: 1,
                confidence: 0.7,
            }],
            graphs: vec![semantic_graph(), semantic_graph()],
            node_mappings: vec![SemanticNodeMapping {
                corresponding_member: 1,
                canonical: 0,
                corresponding: 0,
            }],
        });
        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(
            value["groups"][0]["semantic"]["rules"][0]["id"],
            "sequence-pipeline-v1"
        );
        assert_eq!(
            value["groups"][0]["semantic"]["graphs"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
        assert!(schema["$defs"]["group"]["properties"]["semantic"].is_object());
        assert!(schema["$defs"]["semantic_evidence"].is_object());
    }

    #[test]
    fn semantic_finding_detail_keeps_graphs_and_mappings_readable() {
        let detail = FindingDetail {
            member: fragment_group().members.remove(0),
            group: GroupRef {
                fingerprint: "0e".repeat(16),
                clone_type: "restricted-semantic".to_string(),
                scope: CloneScope::Unit.name().to_string(),
                confidence: 0.7,
                priority: None,
                members: 2,
                boilerplate: None,
                test_code: false,
                split_pair: true,
                similarity: None,
                semantic: Some(SemanticEvidence {
                    schema_version: "sog-v1".to_string(),
                    rules: vec![SemanticRuleEvidence {
                        id: "sequence-pipeline-v1".to_string(),
                        version: 1,
                        confidence: 0.7,
                    }],
                    graphs: vec![semantic_graph(), semantic_graph()],
                    node_mappings: vec![SemanticNodeMapping {
                        corresponding_member: 1,
                        canonical: 0,
                        corresponding: 0,
                    }],
                }),
                suppressed: None,
            },
            scan_run: 3,
            source_artifact_mappings: Vec::new(),
            clone_group_savings: Vec::new(),
        };
        let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
        assert_eq!(
            json["group"]["semantic"]["graphs"].as_array().map(Vec::len),
            Some(2)
        );

        let mut text = Vec::new();
        detail.render_text(&mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("semantic evidence: sog-v1"));
        assert!(text.contains("rule sequence-pipeline-v1@1"));
        assert!(text.contains("graph 1: source -> collect"));
        assert!(text.contains("node mapping: 0→0"));
    }

    #[test]
    fn cross_language_group_detail_keeps_closed_evidence_and_origins_readable() {
        let detail = CrossLanguageGroupDetail {
            schema_version: "cross-language-explain-v1",
            group_id: "ab".repeat(16),
            comparison_id: "cd".repeat(16),
            policy_version: "cross-language-semantic-v1".to_string(),
            root_path: "/work/project".to_string(),
            origin_variants: vec!["cpp-variant".to_string(), "rust-variant".to_string()],
            rule_id: "cross-language-sequence-pipeline-v1".to_string(),
            rule_version: 1,
            semantic_confidence: 0.55,
            correspondence_ids: vec!["sequence-map-v1".to_string()],
            members: vec![CrossLanguageGroupMemberDetail {
                origin_variant: "rust-variant".to_string(),
                language: "rust".to_string(),
                file: "rust/src/lib.rs".to_string(),
                start_line: 3,
                end_line: 6,
                unit: Some("map_values".to_string()),
                graph: semantic_graph(),
            }],
        };

        let json: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
        assert_eq!(json["schema_version"], "cross-language-explain-v1");
        assert_eq!(json["correspondence_ids"][0], "sequence-map-v1");
        assert_eq!(json["members"][0]["graph"]["schema_version"], "sog-v1");
        let mut text = Vec::new();
        detail.render_text(&mut text).unwrap();
        let text = String::from_utf8(text).unwrap();
        assert!(text.contains("cross-language semantic group"));
        assert!(text.contains("sequence-map-v1"));
        assert!(text.contains("rust rust/src/lib.rs:3-6 (rust-variant)"));
        assert!(text.contains("graph sog-v1: source -> collect"));
    }

    #[test]
    fn a_scored_group_reports_every_dimension_and_marks_the_absent_one() {
        let mut report = sample_report();
        report.summary.groups.type_3 = 1;
        report.groups.push(structural_group());
        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();

        let similarity = &value["groups"][2]["similarity"];
        assert_eq!(similarity["composite"], 0.82);
        assert_eq!(similarity["min_pairwise"], 0.79);
        assert_eq!(similarity["weight_version"], "structural-verify-v1");
        assert_eq!(similarity["confidence_band"], "medium");
        assert_eq!(value["groups"][2]["identifier_jaccard"], 0.5);
        assert_eq!(
            value["groups"][2]["priority"]["inputs"]["identifier_jaccard"],
            0.5
        );
        assert_eq!(
            value["groups"][2]["priority"]["inputs"]["api_similarity"],
            0.75
        );
        assert_eq!(value["groups"][2]["body_materiality"]["call_count"], 3);
        // Unavailable, not guessed: the dimension is reported as absent.
        assert_eq!(similarity["type_similarity"], serde_json::Value::Null);
        // A mode that scores no dimensions says so rather than omitting the key.
        assert_eq!(value["groups"][0]["similarity"], serde_json::Value::Null);
        assert_eq!(value["summary"]["groups"]["type_3"], 1);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("type-1 2, type-2 0, type-3 1"));
        assert!(text.contains(
            "similarity: composite 0.82 (lexical 0.71, structural 0.88, \
             control-flow 0.90, type n/a, api 0.75); cohesion 0.79; \
             confidence medium [structural-verify-v1]"
        ));
        assert!(text.contains("raw identifiers 0.50 Jaccard"));
        assert!(text.contains("body evidence: loop yes"));
    }

    #[test]
    fn a_group_standing_where_a_gone_one_stood_says_so_and_the_rest_stay_quiet() {
        let mut report = sample_report();
        report.groups[0].baseline = Some(GroupBaseline {
            state: GROUP_NEW.to_string(),
            derived_from: Some(Derivation {
                group: "aa11".to_string(),
                shared_sites: 2,
            }),
        });
        report.groups[1].baseline = Some(GroupBaseline {
            state: GROUP_CONTINUING.to_string(),
            derived_from: None,
        });

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(
            text.contains("new since the baseline, standing where aa11 stood (2 occurrence(s)"),
            "{text}"
        );
        // Continuing is the unremarkable case, and marking every one of them
        // would bury the one that matters.
        assert_eq!(text.matches("since the baseline").count(), 1, "{text}");
    }

    #[test]
    fn a_comparison_says_how_much_went_as_well_as_how_many() {
        let mut report = sample_report();
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            mode: BASELINE_COMPARE.to_string(),
            matched: 8,
            stale: 4,
            appeared: 21,
            stale_tokens: 3400,
            appeared_tokens: 900,
            gone: vec![GoneGroup {
                group: "aa11".to_string(),
                clone_type: "type-2".to_string(),
                duplicated_tokens: 3400,
                anchor: Some(GoneAnchor {
                    file: "src/gone.rs".to_string(),
                    start_line: 10,
                    end_line: 40,
                    unit: Some("validate".to_string()),
                }),
            }],
            mismatch: None,
            caveat: None,
        });

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        // 21 new against 4 gone reads as a regression until the sizes are on
        // the same line: the four that went were most of the duplication.
        assert!(
            text.contains(
                "since it was recorded: 4 gone (-3400 repeated tokens), 21 new (+900), 8 unchanged"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "gone aa11 type-2 (3400 repeated tokens), last seen at src/gone.rs:10 in validate"
            ),
            "{text}"
        );
    }

    #[test]
    fn json_field_names_appear_in_the_shipped_schema() {
        let schema: serde_json::Value = serde_json::from_str(JSON_SCHEMA).unwrap();
        assert_eq!(
            schema["properties"]["schema_version"]["const"],
            i64::from(SCHEMA_VERSION)
        );
        let mut report = sample_report();
        report.groups.push(structural_group());
        report.groups.push(fragment_group());
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            mode: BASELINE_SUPPRESS.to_string(),
            matched: 11,
            stale: 1,
            appeared: 3,
            stale_tokens: 320,
            appeared_tokens: 90,
            gone: vec![GoneGroup {
                group: "aa11".to_string(),
                clone_type: "type-2".to_string(),
                duplicated_tokens: 320,
                anchor: Some(GoneAnchor {
                    file: "src/gone.rs".to_string(),
                    start_line: 10,
                    end_line: 40,
                    unit: Some("validate".to_string()),
                }),
            }],
            mismatch: Some("recorded under another build variant".to_string()),
            caveat: Some("grouped under different rules".to_string()),
        });
        report.groups[0].baseline = Some(GroupBaseline {
            state: GROUP_NEW.to_string(),
            derived_from: Some(Derivation {
                group: "aa11".to_string(),
                shared_sites: 2,
            }),
        });
        let value: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        let baseline_schema = &schema["$defs"]["summary"]["properties"]["baseline"]["properties"];
        let group_baseline_schema =
            &schema["$defs"]["group"]["properties"]["baseline"]["properties"];
        let checks = [
            (&value["groups"][3], &schema["$defs"]["group"]["properties"]),
            (&value["summary"]["baseline"], baseline_schema),
            (
                &value["summary"]["baseline"]["gone"][0],
                &baseline_schema["gone"]["items"]["properties"],
            ),
            (
                &value["summary"]["baseline"]["gone"][0]["anchor"],
                &baseline_schema["gone"]["items"]["properties"]["anchor"]["properties"],
            ),
            (&value["groups"][0]["baseline"], group_baseline_schema),
            (
                &value["groups"][0]["baseline"]["derived_from"],
                &group_baseline_schema["derived_from"]["properties"],
            ),
            (&value, &schema["properties"]),
            (&value["run"], &schema["$defs"]["run"]["properties"]),
            (&value["summary"], &schema["$defs"]["summary"]["properties"]),
            (
                &value["summary"]["groups"],
                &schema["$defs"]["summary"]["properties"]["groups"]["properties"],
            ),
            (&value["groups"][0], &schema["$defs"]["group"]["properties"]),
            (
                &value["groups"][0]["members"][0],
                &schema["$defs"]["member"]["properties"],
            ),
            (
                &value["groups"][1]["suppressed"],
                &schema["$defs"]["suppression"]["properties"],
            ),
            (
                &value["groups"][2]["similarity"],
                &schema["$defs"]["similarity"]["properties"],
            ),
            (
                &value["run"]["ranking"],
                &schema["$defs"]["ranking"]["properties"],
            ),
            (
                &value["groups"][0]["priority"],
                &schema["$defs"]["priority"]["properties"],
            ),
            (
                &value["groups"][0]["priority"]["inputs"],
                &schema["$defs"]["priority_inputs"]["properties"],
            ),
        ];
        for (object, properties) in checks {
            for key in object.as_object().unwrap().keys() {
                assert!(
                    properties.get(key).is_some(),
                    "field {key:?} missing from the shipped schema"
                );
            }
        }
    }

    #[test]
    fn a_baseline_that_covered_nothing_says_so_rather_than_reading_as_success() {
        let mut report = sample_report();
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            mode: BASELINE_SUPPRESS.to_string(),
            matched: 0,
            stale: 12,
            appeared: 0,
            stale_tokens: 0,
            appeared_tokens: 0,
            gone: Vec::new(),
            mismatch: Some("recorded under build variant aaaa in fast mode".to_string()),
            caveat: None,
        });
        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("baseline codehelion-baseline.json: 0 of 12 entries matched"));
        // Without this the run is indistinguishable from one whose baseline
        // hid everything it was meant to.
        assert!(text.contains("warning: this baseline hid nothing"));

        // A baseline that applies says only what it did.
        report.summary.baseline = Some(BaselineStatus {
            file: "codehelion-baseline.json".to_string(),
            entries: 12,
            mode: BASELINE_SUPPRESS.to_string(),
            matched: 11,
            stale: 1,
            appeared: 0,
            stale_tokens: 0,
            appeared_tokens: 0,
            gone: Vec::new(),
            mismatch: None,
            caveat: None,
        });
        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("11 of 12 entries matched, 1 no longer found"));
        assert!(!text.contains("warning:"));
    }

    #[test]
    fn text_view_truncates_with_an_explicit_count() {
        let mut buffer = Vec::new();
        sample_report()
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("lines: 40; tokens: 200"));
        assert!(text.contains("... and 2 more occurrences"));
        assert!(!text.contains("src/file6.rs"));
        assert!(!text.contains("vendor/a.rs")); // suppressed and not requested
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn text_view_states_each_groups_file_spread() {
        let mut report = sample_report();
        report.groups[0].priority.inputs.files = 1;
        report.groups[1].priority.inputs.files = 2;
        report.groups[1].priority.inputs.directories = 1;
        report.groups[1].suppressed = None;
        let mut third = fragment_group();
        third.priority.inputs.files = 2;
        third.priority.inputs.directories = 2;
        report.groups.push(third);

        let mut buffer = Vec::new();
        report
            .render_text(TextOptions::default(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("[within one file]"));
        assert!(text.contains("[within one directory]"));
        assert!(text.contains("[across directories]"));
    }

    #[test]
    fn verbose_text_lists_every_member_and_suppressed_section_is_opt_in() {
        let opts = TextOptions {
            verbose: true,
            color: false,
            show_suppressed: true,
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("src/file6.rs"));
        assert!(!text.contains("more occurrences"));
        assert!(text.contains("suppressed groups:"));
        assert!(text.contains("[suppressed: path glob \"vendor/**\"]"));
    }

    #[test]
    fn the_pipeline_counts_are_detail_the_verbose_view_asks_for() {
        let render = |verbose| {
            let opts = TextOptions {
                verbose,
                color: false,
                show_suppressed: false,
            };
            let mut buffer = Vec::new();
            sample_report().render_text(opts, &mut buffer).unwrap();
            String::from_utf8(buffer).unwrap()
        };
        let verbose = render(true);
        assert!(verbose.contains("candidate pipeline:"));
        assert!(verbose.contains("tokens"));
        assert!(verbose.contains("(dropped: high frequency 3)"));
        // A cause that dropped nothing says nothing.
        assert!(!verbose.contains("hash collision"));
        assert!(!render(false).contains("candidate pipeline:"));
    }

    #[test]
    fn colored_text_uses_ansi_codes_only_when_enabled() {
        let opts = TextOptions {
            verbose: false,
            color: true,
            show_suppressed: false,
        };
        let mut buffer = Vec::new();
        sample_report().render_text(opts, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("\x1b[1mcodehelion scan (fast mode)\x1b[0m"));
        assert!(text.contains("\x1b[36m"));
    }

    #[test]
    fn finding_detail_shares_the_member_shape_across_views() {
        let detail = FindingDetail {
            member: Member {
                language: "rust".to_string(),
                finding_id: "ab".repeat(16),
                content: "c0".repeat(16),
                file: "src/lib.rs".to_string(),
                start_line: 3,
                end_line: 12,
                unit: Some("checksum".to_string()),
                boilerplate: None,
                tokens: 64,
                canonical: true,
            },
            group: GroupRef {
                fingerprint: "cd".repeat(16),
                clone_type: "type-1".to_string(),
                scope: "unit".to_string(),
                confidence: 1.0,
                priority: None,
                members: 2,
                boilerplate: None,
                test_code: false,
                split_pair: false,
                similarity: None,
                semantic: None,
                suppressed: None,
            },
            scan_run: 7,
            source_artifact_mappings: Vec::new(),
            clone_group_savings: Vec::new(),
        };
        let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
        assert_eq!(value["finding_id"], "ab".repeat(16));
        assert_eq!(value["group"]["clone_type"], "type-1");
        assert_eq!(value["scan_run"], 7);
        // A Fast-mode occurrence measured no dimensions; the field is present
        // and null rather than filled with a guess.
        assert!(value["group"]["similarity"].is_null());

        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains(&format!("finding {}", "ab".repeat(16))));
        assert!(text.contains("location: src/lib.rs:3-12"));
        assert!(text.contains("canonical: yes"));
        assert!(text.contains("2 instances"));
    }

    #[test]
    fn finding_detail_exposes_mapping_evidence_and_separate_estimate_confidences() {
        let detail = FindingDetail {
            member: fragment_group().members.remove(0),
            group: GroupRef {
                fingerprint: "0e".repeat(16),
                clone_type: "type-1".to_string(),
                scope: SCOPE_FRAGMENT.to_string(),
                confidence: 1.0,
                priority: None,
                members: 2,
                boilerplate: None,
                test_code: false,
                split_pair: false,
                similarity: None,
                semantic: None,
                suppressed: None,
            },
            scan_run: 3,
            source_artifact_mappings: vec![SourceArtifactMappingDetail {
                artifact_analysis_id: 12,
                artifact_symbol_fingerprint: "ab".repeat(16),
                source_build_variant_fingerprint: "cd".repeat(16),
                artifact_build_variant_fingerprint: "ef".repeat(16),
                confidence: "ambiguous".to_string(),
                evidence: MappingEvidence::new(
                    vec![MappingEvidenceFact::Dwarf {
                        source_path: "src/lib.rs".to_string(),
                    }],
                    1,
                    true,
                ),
                attributed_bytes: Some(8),
            }],
            clone_group_savings: vec![CloneGroupSavingsDetail {
                artifact_analysis_id: 12,
                source_build_variant_fingerprint: "cd".repeat(16),
                artifact_build_variant_fingerprint: "ef".repeat(16),
                duplicated_bytes: 8,
                estimated_refactor_savings_bytes: -2,
                mapping_confidence: "high".to_string(),
                clone_confidence: 1.0,
                model_confidence: "low".to_string(),
                savings_confidence: "low".to_string(),
                model_schema_version: "refactor-savings-model-v1".to_string(),
                assumptions: serde_json::json!([{
                    "kind": "shared_implementation_retains_copies",
                    "copies": 1,
                }]),
            }],
        };

        let value: serde_json::Value = serde_json::from_str(&detail.to_json().unwrap()).unwrap();
        assert_eq!(
            value["source_artifact_mappings"][0]["evidence"]["facts"][0]["kind"],
            "dwarf"
        );
        assert_eq!(
            value["source_artifact_mappings"][0]["evidence"]["has_conflict"],
            true
        );
        assert_eq!(
            value["clone_group_savings"][0]["estimated_refactor_savings_bytes"],
            -2
        );
        assert_eq!(value["clone_group_savings"][0]["model_confidence"], "low");
        assert_eq!(
            value["clone_group_savings"][0]["source_build_variant_fingerprint"],
            "cd".repeat(16)
        );
        assert_eq!(
            value["clone_group_savings"][0]["assumptions"][0]["kind"],
            "shared_implementation_retains_copies"
        );

        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("source-artifact mappings:"));
        assert!(text.contains("conflicting evidence retained"));
        assert!(text.contains("refactoring estimates (not guaranteed):"));
        assert!(text.contains("-2 estimated bytes"));
        assert!(text.contains(&format!("source build variant: {}", "cd".repeat(16))));
        assert!(text.contains(&format!("artifact build variant: {}", "ef".repeat(16))));
        assert!(text.contains("model schema: refactor-savings-model-v1"));
        assert!(text.contains("shared_implementation_retains_copies"));
    }

    #[test]
    fn a_structural_occurrence_explains_itself_with_the_recorded_evidence() {
        let detail = FindingDetail {
            member: Member {
                language: "rust".to_string(),
                finding_id: "ef".repeat(16),
                content: "c0".repeat(16),
                file: "src/b.rs".to_string(),
                start_line: 1,
                end_line: 20,
                unit: Some("beta".to_string()),
                boilerplate: None,
                tokens: 90,
                canonical: false,
            },
            group: GroupRef {
                fingerprint: "cd".repeat(16),
                clone_type: "type-3".to_string(),
                scope: "unit".to_string(),
                confidence: 0.87,
                priority: None,
                members: 2,
                boilerplate: Some("macro-repetition".to_string()),
                test_code: false,
                split_pair: false,
                similarity: Some(Similarity {
                    weight_version: "structural-verify-v1".to_string(),
                    lexical: 0.71,
                    structural: 0.92,
                    control_flow: 1.0,
                    type_similarity: None,
                    api: Some(0.8),
                    composite: 0.87,
                    min_pairwise: 0.87,
                    confidence_band: Some("medium".to_string()),
                }),
                semantic: None,
                suppressed: Some(Suppression {
                    kind: SuppressionKind::Rule,
                    reason: None,
                    scope: Some("symbol_pattern".to_string()),
                    pattern: Some("beta".to_string()),
                }),
            },
            scan_run: 9,
            source_artifact_mappings: Vec::new(),
            clone_group_savings: Vec::new(),
        };
        let mut buffer = Vec::new();
        detail.render_text(&mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("similarity: composite 0.87"));
        // The unmeasured dimension is named, never guessed.
        assert!(text.contains("type n/a"));
        assert!(text.contains("confidence medium"));
        assert!(text.contains("boilerplate: macro-repetition"));
        // A suppressed finding is still recorded and still explainable.
        assert!(text.contains("suppressed: symbol glob \"beta\""));
    }

    #[test]
    fn an_unrecorded_confidence_band_prints_as_absent() {
        let similarity = Similarity {
            weight_version: "structural-verify-v1".to_string(),
            lexical: 0.5,
            structural: 0.5,
            control_flow: 0.5,
            type_similarity: None,
            api: Some(0.5),
            composite: 0.5,
            min_pairwise: 0.5,
            confidence_band: None,
        };
        assert!(similarity.line().contains("confidence n/a"));
    }
}
