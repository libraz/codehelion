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
//! ([`JSON_SCHEMA`], `schema/scan-report-v2.schema.json`) describes the
//! complete current format.
//!
//! [`sarif`] renders the same value as a SARIF 2.1.0 log for static-analysis
//! consumers.

pub mod sarif;

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::io::{self, Write};

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::{CloneClass, CloneScope};
use codehelion_core::priority::{self, GroupFacts, Weights};
use serde::Serialize;

use crate::config::Suppression as SuppressionConfig;

mod schema;

pub use schema::{
    BASELINE_COMPARE, BASELINE_SUPPRESS, FINDING_DETAIL_JSON_SCHEMA, FINDING_DETAIL_SCHEMA_URI,
    FINDING_DETAIL_SCHEMA_VERSION, GROUP_CONTINUING, GROUP_EXPANDED, GROUP_NEW, JSON_SCHEMA,
    SCHEMA_VERSION,
};
use schema::{GONE_LISTED, SCOPE_FRAGMENT, SHORT_ID_CHARS, TEXT_GROUP_LIMIT, TEXT_MEMBER_LIMIT};

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
    /// Incomplete local mirrors attached to an established group. They are
    /// not group members and are kept separate so primary clone membership
    /// stays a cohesive relation.
    pub siblings: Vec<GroupSiblings>,
    /// Bounded LSH proposals immediately below the primary near-match estimate
    /// gate. They are diagnostic telemetry, never findings or group members.
    pub near_misses: Vec<NearMiss>,
    /// What the recorded seam ledger costs this repository, when `codehelion
    /// seam` has measured it.
    ///
    /// Absent rather than empty when no seam run has been recorded for this
    /// tree: a ledger nobody has evaluated and a ledger whose seams cost
    /// nothing are different facts, and one shape for both would report the
    /// first as the second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seam: Option<SeamReport>,
}

impl Report {
    /// Put run-scoped supplemental groups in the same stable order on a fresh
    /// scan and on a database replay. Their ownership is the public key; the
    /// ranked primary group order is intentionally independent of it. The
    /// nested content/finding key mirrors the store's fragment ordering while
    /// remaining stable when two siblings share content.
    pub(crate) fn order_supplemental(&mut self) {
        for group in &mut self.siblings {
            group.siblings.sort_unstable_by(|left, right| {
                left.member
                    .content
                    .cmp(&right.member.content)
                    .then_with(|| left.member.finding_id.cmp(&right.member.finding_id))
            });
        }
        self.siblings
            .sort_unstable_by(|left, right| left.group_fingerprint.cmp(&right.group_fingerprint));
    }

    /// Derive supplemental totals from the final serialized vectors.
    ///
    /// Fresh scans and replay build those vectors through different paths, so
    /// counts must be taken after both have been populated. In particular,
    /// suppressed entries remain part of the serialized data and therefore
    /// remain part of these totals.
    pub(crate) fn refresh_supplemental_summary(&mut self) {
        self.summary.siblings = self
            .siblings
            .iter()
            .map(|group| u64::try_from(group.siblings.len()).unwrap_or(u64::MAX))
            .fold(0, u64::saturating_add);
        self.summary.near_misses = u64::try_from(self.near_misses.len()).unwrap_or(u64::MAX);
    }
}

mod identity;
mod model;
mod options;

pub(crate) use identity::{NormalizedGroups, normalize_identities};
pub use model::{
    ArtifactSavings, BaselineStatus, BodyMateriality, BuildVariantInfo, CompilerCoverage,
    ConfigurationInfo, CrossLanguageComparison, CrossLanguageComparisonNotRun, CrossLanguageGroup,
    CrossLanguageMember, CrossVariantComparison, CrossVariantComparisonNotRun, CrossVariantGroup,
    CrossVariantMember, Derivation, DetectorVersion, ExcludedCounts, ExecutionRefusal, FileCounts,
    GoneAnchor, GoneGroup, Group, GroupBaseline, GroupCounts, GroupIdentity, GroupSiblings,
    Guardrails, NearMiss, NearMissUnit, Priority, PriorityInputs, ReportedSeam, RunInfo,
    RunTimings, SeamReport, SemanticEvidence, SemanticNodeMapping, SemanticRuleEvidence, Sibling,
    SiblingSimilarity, Similarity, Summary, SuppressedCounts, TopChurn, TreeChanges,
    UnparsedCounts,
};
pub use model::{IDENTITY_ADOPTED, IDENTITY_RETAINED};
pub use options::{Decoration, TextOptions};

mod ranking;

pub use ranking::{
    FunnelCause, FunnelDrop, FunnelStage, Member, RankingInfo, Sort, Suppression, SuppressionKind,
    UnusedRule, canonical_member, canonical_position, compare_on, duplicated_tokens,
    identity_collapsed, is_search_truncation, order, order_recorded, ranked, ranks_down, restored,
    search_truncated, stored_funnel, stored_identity_collapsed, stored_rules,
    unapplied_suppression_policies, unmeasured_in_this_mode,
};

pub(crate) use ranking::append_stored_identity_stage;

mod render;

pub(crate) fn render_partition_artifact_guidance(
    reports: &[Report],
    out: &mut impl Write,
) -> io::Result<()> {
    render::render_partition_artifact_guidance(reports, out)
}

mod detail;

pub use detail::{
    CloneGroupDetail, CloneGroupSavingsDetail, CrossLanguageGroupDetail,
    CrossLanguageGroupMemberDetail, CrossVariantGroupDetail, CrossVariantGroupMemberDetail,
    FindingDetail, GroupRef, RecordedInputs, RecordedPriority, SiblingDetail,
    SourceArtifactMappingDetail,
};

mod notes;

pub use notes::search_truncation_note;
use notes::{budget_note, depth_truncation_files, nesting_truncation_bodies, severed_note};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub(super) mod tests;
