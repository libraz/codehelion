//! Saying what the run did not look at.
//!
//! SARIF has no result for a thing that was never examined, so each such
//! condition becomes an invocation notification against a descriptor the
//! driver declares.

use super::{Configuration, Message, StaticText};
use crate::report::{CompilerCoverage, FunnelCause, Report};
use serde::Serialize;

/// Rule metadata for one clone classification.
pub(super) struct RuleSpec {
    /// The classification as the report model names it.
    pub(super) class: &'static str,
    /// SARIF rule id.
    pub(super) id: &'static str,
    /// SARIF rule name.
    pub(super) name: &'static str,
    /// One-line description.
    pub(super) short: &'static str,
    /// Full description.
    pub(super) full: &'static str,
}

/// One condition about the run itself that the tool can report.
pub(super) struct NoticeSpec {
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
pub(super) enum Notice {
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
/// fixed for the same reason [`RULES`](super::RULES) does.
///
/// Every entry says one kind of thing — the run saw less than the tree holds —
/// because that is the statement a result set cannot make about itself. How
/// often a helper had to be restarted is deliberately not here: a restart the
/// run recovered from cost no coverage, and one that did not shows up as the
/// files it could not answer for. A notification for it would put a fact about
/// the tool's health in the list a reader is using to judge the tool's reach.
pub(super) const NOTICES: [NoticeSpec; 6] = [
    NoticeSpec {
        kind: Notice::NotAsked,
        id: "coverage/not-asked",
        name: "FilesNoCompilerWasAskedAbout",
        short: "Files analysed without asking a compiler",
        full: "No compiler was asked about these files: no installed helper \
               reads their language, or nothing said which compilation unit \
               they belong to. The reason is given per group, because they \
               call for different things. What is reported about them rests \
               on what their source says alone.",
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

/// Notification metadata, as the driver declares it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NoticeDescriptor {
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
pub(super) struct Notification {
    descriptor: DescriptorReference,
    level: &'static str,
    message: Message,
    properties: NotificationProperties,
}

#[derive(Debug, Serialize)]
pub(super) struct DescriptorReference {
    id: &'static str,
    index: usize,
}

/// Notification property bag: what the sentence says, as numbers a consumer can
/// act on without reading it.
#[derive(Debug, Serialize)]
pub(super) struct NotificationProperties {
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
pub(super) fn notifications(report: &Report) -> Vec<Notification> {
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
pub(super) fn occurrences(kind: Notice, report: &Report) -> Vec<(String, NotificationProperties)> {
    let compiler = report.summary.compiler.as_ref();
    match kind {
        // One per reason, for the reason [`Notice::Unanswered`] is: a file
        // nothing says how to compile and a file whose language no installed
        // helper reads are answered by different work, and a single total
        // would leave a consumer to guess which the run met.
        Notice::NotAsked => not_asked_occurrences(compiler),
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

/// Describe the files no compiler was put to, reason by reason.
pub(super) fn not_asked_occurrences(
    compiler: Option<&CompilerCoverage>,
) -> Vec<(String, NotificationProperties)> {
    compiler
        .into_iter()
        .flat_map(|coverage| {
            coverage
                .not_asked_reasons
                .iter()
                .filter(|(_, count)| **count > 0)
                .map(|(reason, count)| {
                    (
                        format!("{count} file(s) were read without asking a compiler: {reason}"),
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

/// Describe compiler requests that could not supply an answer.
pub(super) fn unanswered_occurrences(
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
pub(super) fn execution_refusal_message(
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
pub(super) fn grouping_ceiling_occurrences(
    report: &Report,
) -> Vec<(String, NotificationProperties)> {
    let relationships = report
        .summary
        .funnel
        .iter()
        .flat_map(|stage| &stage.dropped)
        .filter(|drop| {
            FunnelCause::from_name(&drop.cause) == Some(FunnelCause::TheCeilingCutTheSet)
        })
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
pub(super) fn parser_coverage_occurrences(
    report: &Report,
) -> Vec<(String, NotificationProperties)> {
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
