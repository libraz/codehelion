//! SARIF 2.1.0 view of a scan [`Report`].
//!
//! The log is derived from the same [`Report`] value the text and JSON views
//! render, so no reporter carries less than another: everything the JSON
//! document holds is either a first-class SARIF field here or lives in a
//! property bag under the identical key.
//!
//! # Mapping
//!
//! - One clone group is one `result`. Its primary `location` is the canonical
//!   instance; every member, the canonical one included, is repeated in
//!   `relatedLocations` so a consumer can jump between occurrences.
//! - The stable clone-group id is published in `partialFingerprints` under
//!   [`FINGERPRINT_KEY`], which is what consumers use to recognise the same
//!   group across scans.
//! - A suppressed group is emitted with a SARIF `suppressions` entry rather
//!   than dropped, matching the other views: findings are hidden, never
//!   deleted.
//! - What the run did not see becomes an invocation notification against a
//!   declared descriptor, not only a number in the property bag. See below.
//!
//! # Saying what was not looked at
//!
//! SARIF is shaped around findings, and a finding is something that was found.
//! Nothing in a result set tells a project with little duplication apart from a
//! run that could not read the project — both are short lists. The counts are
//! in the property bag either way, but a bag is where a consumer looks after
//! deciding something is wrong, and this is the fact that decides it.
//!
//! So each such condition is a `toolExecutionNotifications` entry on the
//! invocation, against a descriptor the driver declares. That is the one place
//! the format has for a statement about the analysis rather than about the
//! code, and it reaches consumers that show notifications without being taught
//! this tool's property keys.
//!
//! The run still reports `executionSuccessful`. Reading less of a tree than it
//! holds is an outcome, not a failure — a project with no compilation database
//! is analysed by what its source says, and calling that a failed run would
//! tell somebody to fix a tool that did what it could.
//!
//! # Severity
//!
//! Every clone rule declares the same `level`. Duplication is not a defect
//! class with an inherent severity, and the scan's own ranking (priority, with
//! its inputs) is a different quantity from a consumer's severity axis;
//! collapsing one onto the other would invent a judgement the tool never made.
//! The ranking survives as the order of `results` and in each result's
//! property bag.

use std::collections::BTreeMap;

use serde::Serialize;

use super::{
    ArtifactSavings, BodyMateriality, BuildVariantInfo, CompilerCoverage, DetectorVersion, Group,
    GroupSiblings, Member, Priority, RankingInfo, Report, SCOPE_FRAGMENT, Sibling, Similarity,
    Summary, Suppression, SuppressionKind,
};

/// SARIF version this reporter emits.
pub const SARIF_VERSION: &str = "2.1.0";

/// The published schema document for [`SARIF_VERSION`].
pub const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// Key the stable clone-group id is published under.
///
/// The `/v1` suffix is the SARIF convention for versioning a fingerprint
/// recipe: if how the id is computed ever changes, the key changes with it
/// instead of the same key silently meaning something else.
pub const FINGERPRINT_KEY: &str = "cloneGroupFingerprint/v1";

/// Base id every reported location is relative to.
pub(crate) const SRCROOT: &str = "SRCROOT";

/// The level every clone rule reports at; see the module documentation.
const LEVEL: &str = "note";

/// Rule metadata for one clone classification.
struct RuleSpec {
    /// The classification as the report model names it.
    class: &'static str,
    /// SARIF rule id.
    id: &'static str,
    /// SARIF rule name.
    name: &'static str,
    /// One-line description.
    short: &'static str,
    /// Full description.
    full: &'static str,
}

/// The rule set, in the order it is emitted: a result's `ruleIndex` is a
/// position in this table. The table is fixed rather than derived from the
/// groups present, so the same rule keeps the same index across scans.
const RULES: [RuleSpec; 4] = [
    RuleSpec {
        class: "type-1",
        id: "clone/type-1",
        name: "VerbatimClone",
        short: "Verbatim duplicate code",
        full: "Two or more code fragments are identical once comments and \
               whitespace are removed.",
    },
    RuleSpec {
        class: "type-2",
        id: "clone/type-2",
        name: "RenamedClone",
        short: "Duplicate code with renamed identifiers",
        full: "Two or more code fragments are identical once identifiers and \
               literals are normalized.",
    },
    RuleSpec {
        class: "type-3",
        id: "clone/type-3",
        name: "GappedClone",
        short: "Near-duplicate code with added, removed or changed statements",
        full: "Two or more code fragments agree structurally but differ by \
               added, removed or changed statements. Each result carries the \
               per-dimension similarity evidence it was judged on.",
    },
    RuleSpec {
        class: "restricted-semantic",
        id: "clone/restricted-semantic",
        name: "RestrictedSemanticClone",
        short: "Duplicate processing justified by a registered semantic rule",
        full: "Two or more code fragments match under an explicitly registered, \
               bounded semantic correspondence rule. This does not claim general \
               semantic equivalence.",
    },
];

/// One condition about the run itself that the tool can report.
struct NoticeSpec {
    /// Which condition, so that deciding what to emit is exhaustive rather
    /// than a lookup by string that can quietly match nothing.
    kind: Notice,
    /// SARIF notification id.
    id: &'static str,
    /// SARIF notification name.
    name: &'static str,
    /// One-line description.
    short: &'static str,
    /// Full description.
    full: &'static str,
    /// The level it is reported at.
    level: &'static str,
}

/// The conditions a notification can be about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Notice {
    /// Files that were read without a compiler being asked at all.
    NotAsked,
    /// Files a compiler was asked about and supplied nothing for.
    Unanswered,
    /// Candidate search that stopped at one or more resource ceilings.
    SearchTruncated,
    /// Grouping split a candidate set at its configured ceiling.
    GroupingCeilingCut,
    /// The parser recovered from source it could not fully follow.
    ParserCoverage,
    /// Fast mode could not apply configured structural suppression policies.
    UnappliedSuppressionPolicies,
}

/// The notifications this tool can emit, in the order they are declared: a
/// notification's `descriptor.index` is a position in this table, which stays
/// fixed for the same reason [`RULES`] does.
///
/// Every entry says one kind of thing — the run saw less than the tree holds —
/// because that is the statement a result set cannot make about itself. How
/// often a helper had to be restarted is deliberately not here: a restart the
/// run recovered from cost no coverage, and one that did not shows up as the
/// files it could not answer for. A notification for it would put a fact about
/// the tool's health in the list a reader is using to judge the tool's reach.
const NOTICES: [NoticeSpec; 6] = [
    NoticeSpec {
        kind: Notice::NotAsked,
        id: "coverage/not-asked",
        name: "FilesNoCompilerWasAskedAbout",
        short: "Files analysed without asking a compiler",
        full: "No compiler was asked about these files: no installed helper \
               reads their language, or nothing said which compilation unit \
               they belong to. What is reported about them rests on what their \
               source says alone.",
        level: "note",
    },
    NoticeSpec {
        kind: Notice::Unanswered,
        id: "coverage/unanswered",
        name: "FilesTheCompilerAnsweredNothingFor",
        short: "Files a compiler was asked about and could not answer for",
        full: "A compiler helper was asked about these files and supplied \
               nothing. The reason is given per group, because they call for \
               different things: a project that needs a build script allowed \
               to run is not a helper that died.",
        level: "warning",
    },
    NoticeSpec {
        kind: Notice::SearchTruncated,
        id: "coverage/search-truncated",
        name: "CandidateSearchTruncated",
        short: "Candidate search stopped at a resource ceiling",
        full: "The run stopped examining one or more candidate collections at \
               a configured resource ceiling. Duplication the tree holds may \
               be absent from these results.",
        level: "warning",
    },
    NoticeSpec {
        kind: Notice::GroupingCeilingCut,
        id: "coverage/grouping-ceiling",
        name: "GroupingCeilingCutCandidateSet",
        short: "A grouping ceiling cut a related candidate set",
        full: "A configured grouping ceiling split a related candidate set before every \
               relationship could be checked. Some groups or cross-group relationships may \
               be absent from these results.",
        level: "warning",
    },
    NoticeSpec {
        kind: Notice::ParserCoverage,
        id: "coverage/parser-recovery",
        name: "ParserRecoveredFromUnparsedSource",
        short: "The parser could not fully follow part of the source",
        full: "The parser recovered from source tokens it could not attach to structure. \
               Findings in the affected files may describe only the portion it followed.",
        level: "warning",
    },
    NoticeSpec {
        kind: Notice::UnappliedSuppressionPolicies,
        id: "coverage/unapplied-suppression-policy",
        name: "FastModeCouldNotApplySuppressionPolicies",
        short: "Fast mode could not apply structural suppression policies",
        full: "Fast mode compares tokens but does not classify boilerplate, test-only code, or integer-width families. The named suppression policies were not applied; use Structural or Semantic mode to apply them.",
        level: "note",
    },
];

impl Report {
    /// The report as a SARIF 2.1.0 log document, pretty-printed and
    /// newline-terminated.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails.
    pub fn to_sarif(&self) -> serde_json::Result<String> {
        let mut text = serde_json::to_string_pretty(&Log::from(self))?;
        text.push('\n');
        Ok(text)
    }
}

/// A SARIF log holding this scan's single run.
#[derive(Debug, Serialize)]
struct Log<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [Run<'a>; 1],
}

impl<'a> From<&'a Report> for Log<'a> {
    fn from(report: &'a Report) -> Self {
        Self {
            schema: SARIF_SCHEMA_URI,
            version: SARIF_VERSION,
            runs: [Run::from(report)],
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Run<'a> {
    tool: Tool<'a>,
    automation_details: AutomationDetails,
    original_uri_base_ids: BTreeMap<&'static str, UriBase>,
    invocations: [Invocation; 1],
    results: Vec<ResultEntry<'a>>,
    properties: RunProperties<'a>,
}

impl<'a> From<&'a Report> for Run<'a> {
    fn from(report: &'a Report) -> Self {
        let run = &report.run;
        Self {
            tool: Tool {
                driver: Driver {
                    name: "codehelion",
                    version: &run.tool_version,
                    semantic_version: &run.tool_version,
                    information_uri: env!("CARGO_PKG_REPOSITORY"),
                    rules: RULES.iter().map(Descriptor::from).collect(),
                    // Declared whether or not this run had anything to say
                    // with them, so the catalogue of what the tool can report
                    // is the same document to document.
                    notifications: NOTICES.iter().map(NoticeDescriptor::from).collect(),
                },
            },
            automation_details: AutomationDetails {
                id: format!("codehelion/{}", run.mode),
            },
            original_uri_base_ids: std::iter::once((
                SRCROOT,
                UriBase {
                    uri: root_uri(&run.root),
                },
            ))
            .collect(),
            invocations: [Invocation {
                // A run that read less of a tree than the tree holds still ran.
                execution_successful: true,
                start_time_utc: millisecond_timestamp(&run.started_at),
                end_time_utc: millisecond_timestamp(&run.finished_at),
                tool_execution_notifications: notifications(report),
            }],
            results: report
                .groups
                .iter()
                .map(|group| ResultEntry::new(group, sibling_properties(group, &report.siblings)))
                .collect(),
            properties: RunProperties {
                report_schema_version: report.schema_version,
                mode: &run.mode,
                root: &run.root,
                build_variant: &run.build_variant,
                detector_versions: &run.detector_versions,
                ranking: &run.ranking,
                summary: &report.summary,
                database: &run.database,
                run_id: run.run_id,
                near_misses: &report.near_misses,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct Tool<'a> {
    driver: Driver<'a>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Driver<'a> {
    name: &'static str,
    version: &'a str,
    semantic_version: &'a str,
    information_uri: &'static str,
    rules: Vec<Descriptor>,
    notifications: Vec<NoticeDescriptor>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    id: &'static str,
    name: &'static str,
    short_description: StaticText,
    full_description: StaticText,
    default_configuration: Configuration,
    properties: DescriptorProperties,
}

impl From<&'static RuleSpec> for Descriptor {
    fn from(spec: &'static RuleSpec) -> Self {
        Self {
            id: spec.id,
            name: spec.name,
            short_description: StaticText { text: spec.short },
            full_description: StaticText { text: spec.full },
            default_configuration: Configuration { level: LEVEL },
            properties: DescriptorProperties {
                clone_type: spec.class,
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct StaticText {
    text: &'static str,
}

#[derive(Debug, Serialize)]
struct Configuration {
    level: &'static str,
}

/// Rule property bag, naming the classification with the same vocabulary the
/// other views use.
#[derive(Debug, Serialize)]
struct DescriptorProperties {
    clone_type: &'static str,
}

/// Notification metadata, as the driver declares it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NoticeDescriptor {
    id: &'static str,
    name: &'static str,
    short_description: StaticText,
    full_description: StaticText,
    default_configuration: Configuration,
}

impl From<&'static NoticeSpec> for NoticeDescriptor {
    fn from(spec: &'static NoticeSpec) -> Self {
        Self {
            id: spec.id,
            name: spec.name,
            short_description: StaticText { text: spec.short },
            full_description: StaticText { text: spec.full },
            default_configuration: Configuration { level: spec.level },
        }
    }
}

/// One thing this run has to say about itself.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Notification {
    descriptor: DescriptorReference,
    level: &'static str,
    message: Message,
    properties: NotificationProperties,
}

#[derive(Debug, Serialize)]
struct DescriptorReference {
    id: &'static str,
    index: usize,
}

/// Notification property bag: what the sentence says, as numbers a consumer can
/// act on without reading it.
#[derive(Debug, Serialize)]
struct NotificationProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<u64>,
    /// Which reason a compiler gave, in the vocabulary the JSON report uses.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// Candidate relationships a grouping ceiling left unexamined.
    #[serde(skip_serializing_if = "Option::is_none")]
    relationships: Option<u64>,
    /// Source tokens the parser could not attach to structure.
    #[serde(skip_serializing_if = "Option::is_none")]
    unparsed_tokens: Option<u64>,
    /// Unparsed tokens as a share of the analysed token count.
    #[serde(skip_serializing_if = "Option::is_none")]
    unparsed_share: Option<f64>,
    /// Suppression configuration paths Fast mode could not apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    policies: Option<Vec<String>>,
}

/// Everything this run has to say about what it did not see.
///
/// Driven from the table rather than written out condition by condition, so a
/// notification cannot be declared and then never emitted, or emitted against a
/// descriptor nobody declared.
fn notifications(report: &Report) -> Vec<Notification> {
    let mut notifications = Vec::new();
    for (index, spec) in NOTICES.iter().enumerate() {
        for (text, properties) in occurrences(spec.kind, report) {
            notifications.push(Notification {
                descriptor: DescriptorReference { id: spec.id, index },
                level: spec.level,
                message: Message { text },
                properties,
            });
        }
    }
    notifications
}

/// What one condition has to say about this run, if anything.
///
/// A count of zero says nothing: a run that asked about every file it read is
/// not a run with an empty complaint to file.
fn occurrences(kind: Notice, report: &Report) -> Vec<(String, NotificationProperties)> {
    let compiler = report.summary.compiler.as_ref();
    match kind {
        Notice::NotAsked => compiler
            .filter(|coverage| coverage.not_asked > 0)
            .map(|coverage| {
                (
                    format!(
                        "{} file(s) were read without asking a compiler: no installed helper \
                         reads their language, or nothing said which compilation unit they \
                         belong to",
                        coverage.not_asked
                    ),
                    NotificationProperties {
                        files: Some(coverage.not_asked),
                        reason: None,
                        relationships: None,
                        unparsed_tokens: None,
                        unparsed_share: None,
                        policies: None,
                    },
                )
            })
            .into_iter()
            .collect(),
        // One per reason rather than one total: what to do about a project
        // whose build script was not allowed to run has nothing in common with
        // what to do about a helper that died, and a single number would leave
        // a reader to guess which they have.
        Notice::Unanswered => unanswered_occurrences(compiler),
        Notice::SearchTruncated => {
            if report.summary.search_truncated {
                vec![(
                    "candidate search stopped at a resource ceiling, so duplication this tree \
                     holds may be missing from these results"
                        .to_string(),
                    NotificationProperties {
                        files: None,
                        reason: None,
                        relationships: None,
                        unparsed_tokens: None,
                        unparsed_share: None,
                        policies: None,
                    },
                )]
            } else {
                Vec::new()
            }
        }
        Notice::GroupingCeilingCut => grouping_ceiling_occurrences(report),
        Notice::ParserCoverage => parser_coverage_occurrences(report),
        Notice::UnappliedSuppressionPolicies => {
            (!report.summary.unapplied_suppression_policies.is_empty())
                .then(|| {
                    (
                        format!(
                            "Fast mode did not apply suppression policies that require structural \
                         classifications: {}; run with --mode structural or --mode semantic to \
                         apply them",
                            report.summary.unapplied_suppression_policies.join(", "),
                        ),
                        NotificationProperties {
                            files: None,
                            reason: None,
                            relationships: None,
                            unparsed_tokens: None,
                            unparsed_share: None,
                            policies: Some(report.summary.unapplied_suppression_policies.clone()),
                        },
                    )
                })
                .into_iter()
                .collect()
        }
    }
}

/// Describe compiler requests that could not supply an answer.
fn unanswered_occurrences(
    compiler: Option<&CompilerCoverage>,
) -> Vec<(String, NotificationProperties)> {
    compiler
        .into_iter()
        .flat_map(|coverage| {
            coverage
                .unavailable
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(move |(reason, count)| {
                    let message = execution_refusal_message(coverage, reason, *count)
                        .unwrap_or_else(|| {
                            format!(
                                "a compiler was asked about {count} file(s) and supplied nothing: {reason}"
                            )
                        });
                    (
                        message,
                        NotificationProperties {
                            files: Some(*count),
                            reason: Some(reason.clone()),
                            relationships: None,
                            unparsed_tokens: None,
                            unparsed_share: None,
                            policies: None,
                        },
                    )
                })
        })
        .collect()
}

/// Turn a denied execution class into the policy's actionable explanation.
fn execution_refusal_message(
    coverage: &CompilerCoverage,
    reason: &str,
    files: u64,
) -> Option<String> {
    (reason == "requires_execution")
        .then(|| {
            coverage
                .execution_refusals
                .iter()
                .find(|refusal| refusal.files == files)
                .map(|refusal| format!("{} file(s): {}", refusal.files, refusal.message))
        })
        .flatten()
}

/// State how many relationships a grouping ceiling left unexamined.
fn grouping_ceiling_occurrences(report: &Report) -> Vec<(String, NotificationProperties)> {
    let relationships = report
        .summary
        .funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| drop.cause == "the_ceiling_cut_the_set")
        .map(|drop| drop.count)
        .sum::<u64>();
    (relationships > 0)
        .then(|| {
            (
                format!(
                    "a grouping ceiling left {relationships} candidate relationship(s) \
                     unexamined, so some clone groups may be absent"
                ),
                NotificationProperties {
                    files: None,
                    reason: None,
                    relationships: Some(relationships),
                    unparsed_tokens: None,
                    unparsed_share: None,
                    policies: None,
                },
            )
        })
        .into_iter()
        .collect()
}

/// State the amount of source a recovering parser could not follow.
fn parser_coverage_occurrences(report: &Report) -> Vec<(String, NotificationProperties)> {
    report
        .summary
        .unparsed
        .as_ref()
        .filter(|unparsed| unparsed.tokens > 0)
        .map(|unparsed| {
            (
                format!(
                    "the parser could not follow {} token(s), {:.2}% of the analysed source \
                     across {} file(s)",
                    unparsed.tokens,
                    unparsed.share * 100.0,
                    unparsed.files,
                ),
                NotificationProperties {
                    files: Some(unparsed.files),
                    reason: None,
                    relationships: None,
                    unparsed_tokens: Some(unparsed.tokens),
                    unparsed_share: Some(unparsed.share),
                    policies: None,
                },
            )
        })
        .into_iter()
        .collect()
}

#[derive(Debug, Serialize)]
struct AutomationDetails {
    id: String,
}

#[derive(Debug, Serialize)]
struct UriBase {
    uri: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Invocation {
    execution_successful: bool,
    start_time_utc: String,
    end_time_utc: String,
    /// Left out when the run has nothing to say: an empty array reads as a
    /// report that was checked and came back clean, which is a different claim
    /// from a mode that asks no compiler and never had one to make.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_execution_notifications: Vec<Notification>,
}

/// Run property bag: every scan-level field of the JSON report that SARIF has
/// no first-class place for, under its JSON-report key.
#[derive(Debug, Serialize)]
struct RunProperties<'a> {
    report_schema_version: u32,
    mode: &'a str,
    root: &'a str,
    build_variant: &'a BuildVariantInfo,
    detector_versions: &'a [DetectorVersion],
    ranking: &'a RankingInfo,
    summary: &'a Summary,
    database: &'a str,
    run_id: i64,
    near_misses: &'a [super::NearMiss],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultEntry<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_index: Option<usize>,
    level: &'static str,
    message: Message,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrence_count: Option<usize>,
    locations: Vec<Location<'a>>,
    related_locations: Vec<Location<'a>>,
    partial_fingerprints: BTreeMap<&'static str, &'a str>,
    suppressions: Vec<SuppressionEntry>,
    properties: ResultProperties<'a>,
}

impl<'a> ResultEntry<'a> {
    fn new(group: &'a Group, siblings: &'a [Sibling]) -> Self {
        let rule = RULES.iter().find(|spec| spec.class == group.clone_type);
        let canonical = group
            .members
            .iter()
            .find(|member| member.canonical)
            .or_else(|| group.members.first());
        Self {
            rule_id: rule.map(|spec| spec.id),
            rule_index: RULES.iter().position(|spec| spec.class == group.clone_type),
            level: LEVEL,
            message: Message {
                text: message_text(group),
            },
            occurrence_count: (!group.members.is_empty()).then_some(group.members.len()),
            locations: canonical
                .map(|member| Location::new(member, None, None))
                .into_iter()
                .collect(),
            related_locations: group
                .members
                .iter()
                .enumerate()
                .map(|(index, member)| {
                    Location::new(
                        member,
                        Some(index),
                        Some(occurrence_label(index, group.members.len(), member)),
                    )
                })
                .collect(),
            partial_fingerprints: std::iter::once((FINGERPRINT_KEY, group.fingerprint.as_str()))
                .collect(),
            suppressions: group
                .suppressed
                .as_ref()
                .map(SuppressionEntry::from)
                .into_iter()
                .collect(),
            properties: ResultProperties {
                clone_type: &group.clone_type,
                scope: &group.scope,
                statements: group.statements,
                confidence: group.confidence,
                priority: &group.priority,
                similarity: group.similarity.as_ref(),
                identifier_jaccard: group.identifier_jaccard,
                body_materiality: group.body_materiality.as_ref(),
                boilerplate: group.boilerplate.as_deref(),
                test_code: group.test_code,
                test_code_evidence: group.test_code_evidence,
                width_family: group.width_family,
                split_pair: group.split_pair,
                suppressed: group.suppressed.as_ref(),
                semantic: group.semantic.as_ref(),
                artifact_savings: &group.artifact_savings,
                siblings,
            },
        }
    }
}

/// One line describing the group, with the evidence it was judged on when the
/// mode measured any.
fn message_text(group: &Group) -> String {
    // A run duplicated inside unrelated units is not a duplicated unit; the
    // first words of the message have to say which one this is.
    let subject = match (group.scope.as_str(), group.statements) {
        (SCOPE_FRAGMENT, Some(statements)) => format!("run of {statements} statements"),
        (SCOPE_FRAGMENT, None) => "duplicated run".to_string(),
        // A pair reported on its own overlaps other findings, which nothing
        // else here does, so the message says what it is before anything else.
        _ if group.split_pair => "pair no group holds".to_string(),
        _ => "clone group".to_string(),
    };
    let mut text = format!(
        "{} {subject}: {} occurrences, {} tokens in the largest",
        group.clone_type,
        group.members.len(),
        group.priority.inputs.largest_member_tokens,
    );
    if let Some(similarity) = &group.similarity {
        text.push_str(". ");
        text.push_str(&similarity.line());
    }
    text
}

/// Label for one occurrence inside its group.
fn occurrence_label(index: usize, total: usize, member: &Member) -> String {
    let canonical = if member.canonical {
        " (canonical instance)"
    } else {
        ""
    };
    format!("occurrence {} of {total}{canonical}", index + 1)
}

#[derive(Debug, Serialize)]
struct Message {
    text: String,
}

// Fields are named after the SARIF properties they serialize to, so the
// mapping stays readable against the specification.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Location<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<usize>,
    physical_location: PhysicalLocation,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    logical_locations: Vec<LogicalLocation<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<Message>,
    properties: LocationProperties<'a>,
}

impl<'a> Location<'a> {
    fn new(member: &'a Member, id: Option<usize>, message: Option<String>) -> Self {
        Self {
            id,
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: uri_reference(&member.file),
                    uri_base_id: SRCROOT,
                },
                region: region(member),
            },
            logical_locations: member
                .unit
                .as_deref()
                .map(|name| LogicalLocation { name })
                .into_iter()
                .collect(),
            message: message.map(|text| Message { text }),
            properties: LocationProperties {
                finding_id: &member.finding_id,
                tokens: member.tokens,
                canonical: member.canonical,
            },
        }
    }
}

/// The member's line span, or `None` when it has none to report. SARIF regions
/// are 1-based, so an unknown line is left out rather than reported as line
/// zero.
fn region(member: &Member) -> Option<Region> {
    (member.start_line > 0).then(|| Region {
        start_line: member.start_line,
        end_line: member.end_line.max(member.start_line),
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ArtifactLocation {
    uri: String,
    uri_base_id: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u32,
    end_line: u32,
}

#[derive(Debug, Serialize)]
struct LogicalLocation<'a> {
    name: &'a str,
}

/// Location property bag: the per-occurrence fields of a JSON report member,
/// under their JSON-report keys.
#[derive(Debug, Serialize)]
struct LocationProperties<'a> {
    finding_id: &'a str,
    tokens: u64,
    canonical: bool,
}

#[derive(Debug, Serialize)]
struct SuppressionEntry {
    kind: &'static str,
    justification: String,
}

impl From<&Suppression> for SuppressionEntry {
    fn from(cause: &Suppression) -> Self {
        // Only a marker written into the scanned source is `inSource`; engine
        // noise and configured rules both live outside it.
        let in_source = matches!(cause.kind, SuppressionKind::Rule)
            && cause.scope.as_deref() == Some("inline_comment");
        Self {
            kind: if in_source { "inSource" } else { "external" },
            justification: cause.label(),
        }
    }
}

/// Result property bag: the group fields SARIF has no place for, under their
/// JSON-report keys so the two machine-readable views agree field for field.
#[derive(Debug, Serialize)]
struct ResultProperties<'a> {
    clone_type: &'a str,
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    statements: Option<u64>,
    confidence: f64,
    priority: &'a Priority,
    #[serde(skip_serializing_if = "Option::is_none")]
    similarity: Option<&'a Similarity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier_jaccard: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body_materiality: Option<&'a BodyMateriality>,
    #[serde(skip_serializing_if = "Option::is_none")]
    boilerplate: Option<&'a str>,
    test_code: bool,
    test_code_evidence: Option<codehelion_core::test_code::TestCodeEvidence>,
    width_family: bool,
    split_pair: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressed: Option<&'a Suppression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    semantic: Option<&'a super::SemanticEvidence>,
    artifact_savings: &'a [ArtifactSavings],
    siblings: &'a [Sibling],
}

fn sibling_properties<'a>(group: &'a Group, siblings: &'a [GroupSiblings]) -> &'a [Sibling] {
    siblings
        .iter()
        .find(|entry| entry.group_fingerprint == group.fingerprint)
        .map(|entry| entry.siblings.as_slice())
        .unwrap_or_default()
}

pub(crate) mod uri;

use uri::millisecond_timestamp;
pub(crate) use uri::{root_uri, uri_reference};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
