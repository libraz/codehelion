//! Versioned machine-readable report contracts and stable vocabulary.

use serde::Serialize;

/// Version of the JSON report format.
pub const SCHEMA_VERSION: u32 = 1;

/// The JSON Schema document describing the scan report JSON form.
pub const JSON_SCHEMA: &str = include_str!("../../schema/scan-report-v1.schema.json");

/// Version shared by every machine-readable `codehelion explain` response.
pub const FINDING_DETAIL_SCHEMA_VERSION: &str = "finding-detail-v1";

/// URI of the schema that describes [`FINDING_DETAIL_SCHEMA_VERSION`].
pub const FINDING_DETAIL_SCHEMA_URI: &str = "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/finding-detail-v1.schema.json";

/// The JSON Schema document describing every `codehelion explain` response.
pub const FINDING_DETAIL_JSON_SCHEMA: &str =
    include_str!("../../schema/finding-detail-v1.schema.json");

/// Value used for a group whose members are runs of statements.
pub(super) const SCOPE_FRAGMENT: &str = "fragment";

/// Number of groups the default text report lists.
pub(super) const TEXT_GROUP_LIMIT: usize = 10;

/// Number of members per group the default text report lists.
pub(super) const TEXT_MEMBER_LIMIT: usize = 5;

/// Number of gone baseline entries listed before the omitted count.
pub(super) const GONE_LISTED: usize = 10;

/// Identifier digits a text report prints before the reader asks for more.
///
/// The same prefix length `codehelion explain` accepts, so an abbreviated id
/// can be typed straight back into the tool.
pub(super) const SHORT_ID_CHARS: usize = 8;

/// Baseline mode for hiding what the baseline froze.
pub const BASELINE_SUPPRESS: &str = "suppress";

/// Baseline mode for reporting every group against the baseline.
pub const BASELINE_COMPARE: &str = "compare";

/// State of a group the baseline froze.
pub const GROUP_CONTINUING: &str = "continuing";

/// State of a group the baseline did not freeze.
pub const GROUP_NEW: &str = "new";

/// State of a frozen group with added occurrences.
pub const GROUP_EXPANDED: &str = "expanded";

pub(super) const EXPLAIN_RESPONSE_OCCURRENCE: &str = "occurrence";
pub(super) const EXPLAIN_RESPONSE_CLONE_GROUP: &str = "clone_group";
pub(super) const EXPLAIN_RESPONSE_CROSS_LANGUAGE_GROUP: &str = "cross_language_group";
pub(super) const EXPLAIN_RESPONSE_CROSS_VARIANT_GROUP: &str = "cross_variant_group";
pub(super) const EXPLAIN_RESPONSE_SIBLING: &str = "sibling";

#[derive(Serialize)]
struct FindingDetailEnvelope<'a, T: ?Sized> {
    schema_version: &'static str,
    response_kind: &'static str,
    #[serde(flatten)]
    detail: &'a T,
}

pub(super) fn detail_json<T: Serialize + ?Sized>(
    response_kind: &'static str,
    detail: &T,
) -> serde_json::Result<String> {
    let mut text = serde_json::to_string_pretty(&FindingDetailEnvelope {
        schema_version: FINDING_DETAIL_SCHEMA_VERSION,
        response_kind,
        detail,
    })?;
    text.push('\n');
    Ok(text)
}
