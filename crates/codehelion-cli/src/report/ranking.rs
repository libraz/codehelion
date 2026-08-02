//! Report ordering, persisted-summary restoration, and suppression labels.

use super::{
    Boilerplate, CloneClass, CloneScope, ExcludedCounts, FileCounts, FunnelDropRow, FunnelStageRow,
    Group, GroupCounts, GroupFacts, Guardrails, GuardrailsRow, Ordering, Priority, PriorityInputs,
    Serialize, Similarity, Summary, SummaryRow, SuppressedCounts, SuppressionConfig,
    UnparsedCounts, UnusedRuleRow, VENDORED_SCOPE, Weights, priority,
};

impl Guardrails {
    /// Record the concrete resource ceilings an untrusted invocation used.
    ///
    /// `Limits::clamp_to_untrusted` first materialises the optional pairing
    /// limits. The profile is still supplied as a defensive fallback so this
    /// renderer cannot ever claim a zero or missing effective ceiling.
    #[must_use]
    pub(crate) fn untrusted(
        limits: &crate::config::Limits,
        profile: &codehelion_core::execution::Limits,
    ) -> Self {
        Self {
            profile: "untrusted".to_string(),
            max_file_bytes: limits.max_file_bytes,
            parse_timeout_ms: limits.parse_timeout_ms,
            helper_timeout_ms: limits.helper_timeout_ms,
            posting_cap: limits.posting_cap.unwrap_or(profile.posting_cap),
            pair_budget: limits.pair_budget.unwrap_or(profile.max_candidates),
            near_miss_delta: limits.near_miss_delta.unwrap_or_else(|| {
                codehelion_core::near_match::NearMatchConfig::default().near_miss_delta
            }),
            near_miss_cap: limits.near_miss_cap.unwrap_or_else(|| {
                codehelion_core::near_match::NearMatchConfig::default().near_miss_cap
            }),
            sibling_candidate_budget: limits.sibling_candidate_budget.unwrap_or_else(|| {
                codehelion_core::structural::SiblingConfig::default().candidate_budget
            }),
            sibling_per_group_cap: limits.sibling_per_group_cap.unwrap_or_else(|| {
                codehelion_core::structural::SiblingConfig::default().per_group_cap
            }),
            sibling_total_cap: limits
                .sibling_total_cap
                .unwrap_or_else(|| codehelion_core::structural::SiblingConfig::default().total_cap),
            max_component: limits.max_component,
        }
    }
}

impl From<&GuardrailsRow> for Guardrails {
    fn from(row: &GuardrailsRow) -> Self {
        Self {
            profile: row.profile.clone(),
            max_file_bytes: row.max_file_bytes,
            parse_timeout_ms: row.parse_timeout_ms,
            helper_timeout_ms: row.helper_timeout_ms,
            posting_cap: usize::try_from(row.posting_cap).unwrap_or(usize::MAX),
            pair_budget: usize::try_from(row.pair_budget).unwrap_or(usize::MAX),
            near_miss_delta: codehelion_core::near_match::NearMatchConfig::default()
                .near_miss_delta,
            near_miss_cap: codehelion_core::near_match::NearMatchConfig::default().near_miss_cap,
            sibling_candidate_budget: usize::try_from(row.sibling_candidate_budget)
                .unwrap_or(usize::MAX),
            sibling_per_group_cap: usize::try_from(row.sibling_per_group_cap).unwrap_or(usize::MAX),
            sibling_total_cap: usize::try_from(row.sibling_total_cap).unwrap_or(usize::MAX),
            max_component: usize::try_from(row.max_component).unwrap_or(usize::MAX),
        }
    }
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

/// Whether a funnel drop was imposed by a resource ceiling rather than by an
/// analysis judgement about the candidate itself.
///
/// The funnel retains its cause vocabulary as data so stored reports can be
/// rendered by newer binaries. This predicate is deliberately centralized so
/// adding a ceiling cannot quietly make the default report look complete.
#[must_use]
pub fn is_search_truncation(cause: &str) -> bool {
    matches!(
        cause,
        "high_frequency"
            | "high_frequency_postings"
            | "class_cap"
            | "pair_budget"
            | "verification_budget"
            | "crowded_bucket"
            | "common_skeleton"
            | "common_skeleton_postings"
            | "bucket_member_cap"
            | "the_ceiling_cut_the_set"
    )
}

/// Whether any candidate-search ceiling made the report potentially
/// incomplete.
#[must_use]
pub fn search_truncated(funnel: &[FunnelStage]) -> bool {
    funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .any(|drop| is_search_truncation(&drop.cause))
}

impl FunnelDrop {
    /// The cause as it reads in the text views.
    #[must_use]
    pub fn label(&self) -> String {
        self.cause.replace('_', " ")
    }
}

/// An axis a report can be put in order on.
///
/// The ranking exists because no single measure orders duplication well, and
/// the same reasoning says a reader may know which measure matters to the work
/// in front of them. Offering the axes outright is cheaper than pretending the
/// composed value fits every job — and it is what a reader who distrusts the
/// ranking would otherwise do by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// The composed ranking value.
    #[default]
    Priority,
    /// Raw identifier agreement against the canonical member: how much of the
    /// vocabulary the copies share before normalization.
    IdentifierJaccard,
    /// Tokens the group repeats past its canonical member.
    DuplicatedTokens,
    /// Number of occurrences.
    Instances,
}

impl Sort {
    /// What this axis is called on the command line and in a heading.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Priority => "priority",
            Self::IdentifierJaccard => "identifier Jaccard",
            Self::DuplicatedTokens => "duplicated tokens",
            Self::Instances => "instances",
        }
    }

    /// Which of two entries the axis puts first, before ties are broken.
    ///
    /// Each axis compares in its own arithmetic rather than through a shared
    /// numeric key: a count is an integer, and widening one to compare it
    /// against a score would trade exactness for a uniformity nothing needs.
    fn compare(self, a: &Group, b: &Group) -> Ordering {
        match self {
            Self::Priority => descending(Some(a.priority.value), Some(b.priority.value)),
            Self::IdentifierJaccard => descending(a.identifier_jaccard, b.identifier_jaccard),
            Self::DuplicatedTokens => duplicated_tokens(b).cmp(&duplicated_tokens(a)),
            Self::Instances => b
                .priority
                .inputs
                .instances
                .cmp(&a.priority.inputs.instances),
        }
    }
}

/// Biggest first, with a measurement nobody made last.
///
/// Absent is not the same as low: putting the unmeasured in with the worst
/// would report a guess as a reading.
fn descending(a: Option<f64>, b: Option<f64>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => b.total_cmp(&a),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Compare two entries on one axis alone, biggest first, ties broken by
/// fingerprint so the result is the same on every machine.
///
/// Separate from [`order`] because a view rebuilt from the database has the
/// entries but not the configuration that decides what gets ranked down, and
/// the axis has to mean the same thing in both.
#[must_use]
pub fn compare_on(a: &Group, b: &Group, sort: Sort) -> Ordering {
    sort.compare(a, b)
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

/// Tokens a group repeats: everything past the one copy a reader would keep.
#[must_use]
pub fn duplicated_tokens(group: &Group) -> u64 {
    let total: u64 = group.members.iter().map(|member| member.tokens).sum();
    let canonical = group
        .members
        .iter()
        .find(|member| member.canonical)
        .map_or(0, |member| member.tokens);
    total.saturating_sub(canonical)
}

/// Put the entries in the order every view of a report shows them in.
///
/// Three keys, in this order: whether the configuration ranks the entry down,
/// then the chosen axis descending, then fingerprint ascending. The first is
/// what keeps boilerplate and test-suite repetition below the code under test
/// without changing what either of them scored; the last makes ties come out
/// the same on every machine. Changing the axis changes only the middle key —
/// what is ranked down stays ranked down, because that is a statement about
/// the finding rather than about which measure the reader is following.
///
/// One function rather than one per pipeline: the order is a property of the
/// report, and a scan that assembled its entries and a run rebuilt from the
/// database have to agree about it.
pub fn order(groups: &mut [Group], suppression: &SuppressionConfig, sort: Sort) {
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
            .then_with(|| compare_on(a, b, sort))
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
pub fn restored(stored: &SummaryRow, groups: &[Group], analysis_mode: &str) -> Summary {
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
    let funnel: Vec<FunnelStage> = stored
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
        .collect();
    let search_truncated = search_truncated(&funnel);
    Summary {
        files: FileCounts {
            total: stored.analyzed_files.total,
            rust: stored.analyzed_files.rust,
            c: stored.analyzed_files.c,
            cpp: stored.analyzed_files.cpp,
        },
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
            too_large: stored.excluded_too_large,
            binary: stored.excluded_binary,
            unreadable: stored.excluded_unreadable,
            symlinks: stored.excluded_symlinks,
            walk_errors: stored.excluded_walk_errors,
            timed_out: stored.excluded_timed_out,
        },
        baseline: None,
        guardrails: stored.guardrails.as_ref().map(Guardrails::from),
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
            vendored: count(&|group| {
                group
                    .suppressed
                    .as_ref()
                    .and_then(|cause| cause.scope.as_deref())
                    == Some(VENDORED_SCOPE)
            }),
        },
        unused_suppressions: stored
            .unused_suppressions
            .iter()
            .map(|rule| UnusedRule {
                scope: rule.scope.clone(),
                pattern: rule.pattern.clone(),
            })
            .collect(),
        unapplied_suppression_policies: unapplied_suppression_policies(analysis_mode),
        funnel,
        split_components: stored.split_components,
        pair_budget_exhausted: stored.pair_budget_exhausted,
        search_truncated,
    }
}

/// Configured suppression policies that a given analysis mode cannot apply.
///
/// This is derived from the mode rather than stored in the summary row: the
/// limitation is a property of the frontend, and a replay must present the
/// same limitation as the original report.
#[must_use]
pub fn unapplied_suppression_policies(analysis_mode: &str) -> Vec<String> {
    if analysis_mode == "fast" {
        [
            "suppression.boilerplate",
            "suppression.test-code",
            "suppression.width-family",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        Vec::new()
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
    /// Engine noise category or suppression-rule judgement, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Suppression-rule scope, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Suppression-rule pattern, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Whether the stored rule was active, present when `kind` is rule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
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
                    Some("ast_pattern") => self.reason.as_deref().map_or_else(
                        || format!("structural shape: {pattern}"),
                        |reason| format!("{reason}: {pattern}"),
                    ),
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
        let control_flow = self
            .control_flow
            .map_or_else(|| "n/a".to_string(), |value| format!("{value:.2}"));
        let band = self.confidence_band.as_deref().unwrap_or("n/a");
        format!(
            "similarity: composite {:.2} (lexical {:.2}, structural {:.2}, \
             control-flow {control_flow}, type {type_similarity}, api {api}); \
             cohesion {:.2}; confidence {band} [{}]",
            self.composite, self.lexical, self.structural, self.min_pairwise, self.weight_version,
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
