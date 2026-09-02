//! Report ordering, persisted-summary restoration, and suppression labels.

use super::{
    Boilerplate, CloneClass, CloneScope, Group, GroupFacts, Ordering, Priority, PriorityInputs,
    Serialize, Similarity, SuppressionConfig, Weights, priority,
};
use codehelion_store::directory_of;
use std::collections::BTreeMap;

mod funnel;
mod narrower_cut;
mod restored;

#[allow(
    clippy::redundant_pub_crate,
    reason = "the stage appender is crate-internal and reaches the rest of the crate through the report module's re-export"
)]
pub(crate) use funnel::append_stored_identity_stage;
pub use funnel::{
    FunnelCause, FunnelDrop, FunnelStage, identity_collapsed, is_search_truncation,
    search_truncated, stored_funnel, stored_identity_collapsed,
};
use narrower_cut::mark_narrower_cuts;
pub use restored::{
    RankingInfo, Suppression, SuppressionKind, UnusedRule, restored, stored_rules,
    unapplied_suppression_policies, unmeasured_in_this_mode,
};

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

/// Compare two entries on one axis, biggest first, then by the composed
/// ranking, then by fingerprint so the result is the same on every machine.
///
/// A single axis ties often, and the ties are where the reader is left. Raw
/// identifier agreement is the clearest case: a tree with any repetition in it
/// has dozens of entries at exactly 1.00, and ordering those by fingerprint
/// puts the largest and the most trivial of them in hash order, which is the
/// order of nothing. The composed ranking is the best statement available
/// about which of two otherwise indistinguishable entries is worth reading
/// first, so it decides before the identifier does. Fingerprint stays last and
/// still settles the remainder.
///
/// Separate from [`order`] because a view rebuilt from the database has the
/// entries but not the configuration that decides what gets ranked down, and
/// the axis has to mean the same thing in both.
#[must_use]
pub fn compare_on(a: &Group, b: &Group, sort: Sort) -> Ordering {
    sort.compare(a, b)
        .then_with(|| Sort::Priority.compare(a, b))
        .then_with(|| a.fingerprint.cmp(&b.fingerprint))
}

/// Which occurrence of a group is the one it is measured against.
///
/// One rule for every view, because the answer is read by the text listing,
/// the SARIF primary location, and a frozen baseline anchor, and those naming
/// different occurrences of the same group would be three accounts of one
/// fact. A group whose members carry no flag at all — which a partially
/// written or hand-edited database can hold — resolves to its first member
/// rather than to nothing, so the fact stays single-valued.
///
/// Generic over the member type: a report member and a stored member spell the
/// flag differently, and the rule is about neither spelling.
#[must_use]
pub fn canonical_position<T>(members: &[T], flagged: impl Fn(&T) -> bool) -> Option<usize> {
    if members.is_empty() {
        return None;
    }
    Some(members.iter().position(flagged).unwrap_or(0))
}

/// The occurrence a report group is measured against.
#[must_use]
pub fn canonical_member(group: &Group) -> Option<&Member> {
    canonical_position(&group.members, |member| member.canonical)
        .and_then(|index| group.members.get(index))
}

/// Tokens a group repeats: everything past the one copy a reader would keep.
#[must_use]
pub fn duplicated_tokens(group: &Group) -> u64 {
    let total: u64 = group.members.iter().map(|member| member.tokens).sum();
    let canonical = canonical_member(group).map_or(0, |member| member.tokens);
    total.saturating_sub(canonical)
}

/// Put the entries in the order every view of a report shows them in.
///
/// Whether the configuration ranks the entry down comes first, and then
/// [`compare_on`] settles the rest. The rank-down key is what keeps
/// boilerplate and test-suite repetition below the code under test without
/// changing what either of them scored. Changing the axis does not touch it —
/// what is ranked down stays ranked down, because that is a statement about
/// the finding rather than about which measure the reader is following.
///
/// One function rather than one per pipeline: the order is a property of the
/// report, and a scan that assembled its entries and a run rebuilt from the
/// database have to agree about it.
pub fn order(groups: &mut [Group], suppression: &SuppressionConfig, sort: Sort) {
    for group in groups.iter_mut() {
        group.ranked_down = ranks_down(group, suppression);
    }
    settle(groups, sort);
}

/// Whether one finding is placed after ordinary findings by presentation
/// policy, independently of its numeric priority.
#[must_use]
pub fn ranks_down(group: &Group, suppression: &SuppressionConfig) -> bool {
    suppression.ranks_down(
        group
            .boilerplate
            .as_deref()
            .and_then(Boilerplate::from_name),
        group.test_code,
        group.width_family,
        group.split_pair,
    )
}

/// Replay ordering using the rank-down verdict persisted with the run.
pub fn order_recorded(groups: &mut [Group], ranked_down: &BTreeMap<String, bool>, sort: Sort) {
    for group in groups.iter_mut() {
        group.ranked_down = ranked_down
            .get(&group.fingerprint)
            .copied()
            .unwrap_or(false);
    }
    settle(groups, sort);
}

/// Everything a report decides about its findings as a set rather than one at
/// a time: which of them another already reports a wider cut of, and the order
/// they are shown in.
///
/// A scan that assembled its entries and a run rebuilt from the database reach
/// this with the same complete set, and both leave it having answered the same
/// two questions the same way. Answering either of them per pipeline would be
/// two answers to one question about one run.
fn settle(groups: &mut [Group], sort: Sort) {
    mark_narrower_cuts(groups);
    groups.sort_by(|a, b| {
        a.ranked_down
            .cmp(&b.ranked_down)
            .then_with(|| compare_on(a, b, sort))
    });
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
#[derive(Debug, Clone, Serialize)]
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

/// Group fixtures shared by the ranking submodules' tests.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod fixtures {
    use super::{Group, Priority, Suppression, SuppressionKind};
    use crate::suppress::CLONE_ID_SCOPE;

    /// A group the clone id `rule` hid, whose own id starts with that rule.
    pub(super) fn hidden_by_clone_id(fingerprint: &str, rule: &str) -> Group {
        Group {
            fingerprint: fingerprint.to_string(),
            clone_type: "type-1".to_string(),
            scope: "unit".to_string(),
            statements: None,
            confidence: 1.0,
            entropy_bits: 2.0,
            priority: Priority::unranked(),
            identity: None,
            similarity: None,
            identifier_jaccard: None,
            body_materiality: None,
            boilerplate: None,
            test_code: false,
            test_code_evidence: None,
            width_family: false,
            split_pair: false,
            narrower_cut_of: None,
            ranked_down: false,
            suppressed: Some(Suppression {
                kind: SuppressionKind::Rule,
                reason: None,
                scope: Some(CLONE_ID_SCOPE.to_string()),
                pattern: Some(rule.to_string()),
                active: Some(true),
            }),
            baseline: None,
            semantic: None,
            artifact_savings: Vec::new(),
            members: Vec::new(),
        }
    }
}
