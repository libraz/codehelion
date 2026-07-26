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
    BuildVariantInfo, DetectorVersion, Group, Member, Priority, RankingInfo, Report,
    SCOPE_FRAGMENT, Similarity, Summary, Suppression, SuppressionKind,
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
const SRCROOT: &str = "SRCROOT";

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
const RULES: [RuleSpec; 3] = [
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
                execution_successful: true,
                start_time_utc: millisecond_timestamp(&run.started_at),
                end_time_utc: millisecond_timestamp(&run.finished_at),
            }],
            results: report.groups.iter().map(ResultEntry::from).collect(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressions: Option<[SuppressionEntry; 1]>,
    properties: ResultProperties<'a>,
}

impl<'a> From<&'a Group> for ResultEntry<'a> {
    fn from(group: &'a Group) -> Self {
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
                .map(|cause| [SuppressionEntry::from(cause)]),
            properties: ResultProperties {
                clone_type: &group.clone_type,
                scope: &group.scope,
                statements: group.statements,
                confidence: group.confidence,
                priority: &group.priority,
                similarity: group.similarity.as_ref(),
                boilerplate: group.boilerplate.as_deref(),
                test_code: group.test_code,
                split_pair: group.split_pair,
                suppressed: group.suppressed.as_ref(),
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
    boilerplate: Option<&'a str>,
    test_code: bool,
    split_pair: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    suppressed: Option<&'a Suppression>,
}

/// Percent-encode a path as a URI reference relative to [`SRCROOT`].
///
/// Everything outside the unreserved set is escaped, so a path containing
/// spaces or non-ASCII characters still yields a valid URI. Backslashes become
/// separators: a URI path is separated by `/` on every platform.
fn uri_reference(path: &str) -> String {
    let mut uri = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                uri.push(char::from(byte));
            }
            b'\\' => uri.push('/'),
            _ => {
                const HEX: [u8; 16] = *b"0123456789ABCDEF";
                uri.push('%');
                uri.push(char::from(HEX[usize::from(byte >> 4)]));
                uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
        }
    }
    uri
}

/// Absolute `file:` URI for the scan root, with the trailing slash that marks
/// it as a directory the result URIs are resolved against.
fn root_uri(root: &str) -> String {
    let encoded = uri_reference(root);
    let mut uri = String::from("file://");
    if !encoded.starts_with('/') {
        uri.push('/');
    }
    uri.push_str(&encoded);
    if !uri.ends_with('/') {
        uri.push('/');
    }
    uri
}

/// Restate an RFC 3339 UTC timestamp with the millisecond precision SARIF
/// specifies (`yyyy-MM-ddTHH:mm:ss.sssZ`). A value in another shape is passed
/// through unchanged rather than mangled.
fn millisecond_timestamp(value: &str) -> String {
    let Some(rest) = value.strip_suffix('Z') else {
        return value.to_string();
    };
    let (seconds, fraction) = rest.split_once('.').unwrap_or((rest, ""));
    if !seconds.contains('T') {
        return value.to_string();
    }
    let mut millis: String = fraction.chars().take(3).collect();
    while millis.len() < 3 {
        millis.push('0');
    }
    format!("{seconds}.{millis}Z")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::report::tests::{sample_report, structural_group};

    fn sarif(report: &Report) -> serde_json::Value {
        serde_json::from_str(&report.to_sarif().unwrap()).unwrap()
    }

    #[test]
    fn the_log_names_its_version_and_the_tool_that_produced_it() {
        let value = sarif(&sample_report());
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["$schema"], SARIF_SCHEMA_URI);
        assert_eq!(value["runs"].as_array().unwrap().len(), 1);

        let driver = &value["runs"][0]["tool"]["driver"];
        assert_eq!(driver["name"], "codehelion");
        assert_eq!(driver["version"], "0.1.0");
        // The rule table is fixed, so a rule index means the same thing in
        // every log this tool writes.
        let rules = driver["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[2]["id"], "clone/type-3");
        assert_eq!(rules[2]["defaultConfiguration"]["level"], "note");

        let run = &value["runs"][0];
        assert_eq!(run["automationDetails"]["id"], "codehelion/fast");
        assert_eq!(
            run["originalUriBaseIds"]["SRCROOT"]["uri"],
            "file:///work/project/"
        );
        assert_eq!(run["invocations"][0]["executionSuccessful"], true);
        // SARIF timestamps carry milliseconds, not the microseconds the JSON
        // report records.
        assert_eq!(
            run["invocations"][0]["startTimeUtc"],
            "2026-01-01T00:00:00.000Z"
        );
    }

    #[test]
    fn a_group_becomes_one_result_pointing_at_its_canonical_instance() {
        let value = sarif(&sample_report());
        let result = &value["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "clone/type-1");
        assert_eq!(result["ruleIndex"], 0);
        assert_eq!(result["level"], "note");
        assert_eq!(result["occurrenceCount"], 7);
        assert!(
            result["message"]["text"]
                .as_str()
                .unwrap()
                .starts_with("type-1 clone group: 7 occurrences, 80 tokens")
        );

        let primary = &result["locations"][0];
        assert_eq!(
            primary["physicalLocation"]["artifactLocation"]["uri"],
            "src/file0.rs"
        );
        assert_eq!(
            primary["physicalLocation"]["artifactLocation"]["uriBaseId"],
            "SRCROOT"
        );
        assert_eq!(primary["physicalLocation"]["region"]["startLine"], 1);
        assert_eq!(primary["physicalLocation"]["region"]["endLine"], 9);
        assert_eq!(primary["logicalLocations"][0]["name"], "checksum");
        assert_eq!(primary["properties"]["canonical"], true);

        // Every member is reachable, the canonical one included.
        let related = result["relatedLocations"].as_array().unwrap();
        assert_eq!(related.len(), 7);
        assert_eq!(related[0]["id"], 0);
        assert_eq!(
            related[0]["message"]["text"],
            "occurrence 1 of 7 (canonical instance)"
        );
        assert_eq!(related[6]["message"]["text"], "occurrence 7 of 7");
        assert_eq!(
            related[6]["properties"]["finding_id"],
            format!("{:032x}", 6)
        );

        // The stable clone id travels with the result.
        assert_eq!(
            result["partialFingerprints"][FINGERPRINT_KEY],
            "0b".repeat(16)
        );
    }

    #[test]
    fn the_similarity_breakdown_reaches_the_result_intact() {
        let mut report = sample_report();
        report.groups.push(structural_group());
        let value = sarif(&report);
        let result = &value["runs"][0]["results"][2];

        assert_eq!(result["ruleId"], "clone/type-3");
        assert_eq!(result["ruleIndex"], 2);
        let properties = &result["properties"];
        assert_eq!(properties["clone_type"], "type-3");
        assert_eq!(
            properties["priority"]["inputs"]["largest_member_tokens"],
            60
        );
        assert_eq!(properties["similarity"]["composite"], 0.82);
        assert_eq!(
            properties["similarity"]["weight_version"],
            "structural-verify-v4"
        );
        // The dimension the mode could not measure stays absent here too.
        assert_eq!(
            properties["similarity"]["type_similarity"],
            serde_json::Value::Null
        );
        assert!(
            result["message"]["text"]
                .as_str()
                .unwrap()
                .contains("type n/a")
        );
        // The classified shape travels with the result too, so no reporter
        // says less about a group than another.
        let mut classified = sample_report();
        let mut group = structural_group();
        group.boilerplate = Some("macro-repetition".to_string());
        classified.groups.push(group);
        assert_eq!(
            sarif(&classified)["runs"][0]["results"][2]["properties"]["boilerplate"],
            "macro-repetition"
        );

        // As does whether the group lives wholly in a test suite, which is why
        // it may sit low in a report that still lists it.
        let mut suite = sample_report();
        let mut group = structural_group();
        group.test_code = true;
        suite.groups.push(group);
        let log = sarif(&suite);
        assert_eq!(
            log["runs"][0]["results"][2]["properties"]["test_code"],
            true
        );
        assert_eq!(
            log["runs"][0]["results"][0]["properties"]["test_code"],
            false
        );

        // A mode that scores no dimensions omits the key rather than
        // inventing values.
        assert!(
            value["runs"][0]["results"][0]["properties"]
                .get("similarity")
                .is_none()
        );
    }

    #[test]
    fn a_suppressed_group_is_reported_as_suppressed_not_dropped() {
        let value = sarif(&sample_report());
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2, "the hidden group is still reported");

        let suppression = &results[1]["suppressions"][0];
        assert_eq!(suppression["kind"], "external");
        assert_eq!(suppression["justification"], "path glob \"vendor/**\"");
        assert_eq!(results[1]["properties"]["suppressed"]["scope"], "path_glob");
        assert!(results[0].get("suppressions").is_none());
    }

    #[test]
    fn an_inline_marker_is_the_only_in_source_suppression() {
        let inline = Suppression {
            kind: SuppressionKind::Rule,
            reason: None,
            scope: Some("inline_comment".to_string()),
            pattern: Some("codehelion:ignore".to_string()),
        };
        assert_eq!(SuppressionEntry::from(&inline).kind, "inSource");

        let noise = Suppression {
            kind: SuppressionKind::Noise,
            reason: Some("low-entropy".to_string()),
            scope: None,
            pattern: None,
        };
        let entry = SuppressionEntry::from(&noise);
        assert_eq!(entry.kind, "external");
        assert_eq!(entry.justification, "low-entropy noise");
    }

    #[test]
    fn the_run_property_bag_keeps_what_sarif_has_no_field_for() {
        let value = sarif(&sample_report());
        let properties = &value["runs"][0]["properties"];
        assert_eq!(properties["report_schema_version"], 2);
        assert_eq!(properties["mode"], "fast");
        assert_eq!(properties["build_variant"]["normalization_version"], 2);
        assert_eq!(properties["detector_versions"][0]["component"], "fp-schema");
        assert_eq!(properties["summary"]["files"]["total"], 2);
        assert_eq!(properties["run_id"], 1);
    }

    #[test]
    fn paths_are_escaped_into_valid_uri_references() {
        assert_eq!(uri_reference("src/lib.rs"), "src/lib.rs");
        assert_eq!(uri_reference("src/a b.rs"), "src/a%20b.rs");
        assert_eq!(uri_reference("src\\win.rs"), "src/win.rs");
        assert_eq!(uri_reference("src/日本.rs"), "src/%E6%97%A5%E6%9C%AC.rs");
        assert_eq!(root_uri("/work/my project"), "file:///work/my%20project/");
        assert_eq!(root_uri("C:\\work"), "file:///C:/work/");
    }

    #[test]
    fn timestamps_are_restated_at_millisecond_precision() {
        assert_eq!(
            millisecond_timestamp("2026-01-01T00:00:00.123456Z"),
            "2026-01-01T00:00:00.123Z"
        );
        assert_eq!(
            millisecond_timestamp("2026-01-01T00:00:00Z"),
            "2026-01-01T00:00:00.000Z"
        );
        // Anything else is passed through rather than mangled.
        assert_eq!(millisecond_timestamp("unknown"), "unknown");
    }

    #[test]
    fn a_member_without_lines_reports_no_region() {
        let mut report = sample_report();
        report.groups[0].members[0].start_line = 0;
        report.groups[0].members[0].end_line = 0;
        let value = sarif(&report);
        let physical = &value["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert!(physical.get("region").is_none());
        assert_eq!(physical["artifactLocation"]["uri"], "src/file0.rs");
    }
}
