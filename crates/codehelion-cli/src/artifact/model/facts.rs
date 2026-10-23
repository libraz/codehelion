//! The scalar facts each report states once, as one table every rendering
//! reads.
//!
//! A fact is written in text as `label: value`, in CSV under its column, and
//! in JSON at its pointer. Adding an entry here is what makes a fact reach all
//! three, so no rendering can carry a fact the others leave out.

use super::{ArtifactComparisonReport, ArtifactReport, ComparisonArtifact};

/// One scalar fact of a report of type `R`.
pub(in crate::artifact) struct ReportFact<R> {
    /// Text label the line opens with.
    pub(in crate::artifact) label: &'static str,
    /// CSV column carrying the fact.
    pub(in crate::artifact) column: &'static str,
    /// JSON pointer to the field carrying the fact in the serialized report.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::artifact) json_pointer: &'static str,
    /// The fact as every rendering writes it, or `None` when the report does
    /// not have it.
    pub(in crate::artifact) value: fn(&R) -> Option<String>,
}

// Derived impls would demand `R: Copy`, which no report is.
impl<R> Clone for ReportFact<R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for ReportFact<R> {}

/// How a list-valued fact is written as one value.
fn listed(items: &[String]) -> Option<String> {
    (!items.is_empty()).then(|| items.join(", "))
}

/// The scalar facts of one artifact report, in text order.
pub(in crate::artifact) const ARTIFACT_FACTS: &[ReportFact<ArtifactReport>] = &[
    ReportFact {
        label: "artifact",
        column: "path",
        json_pointer: "/path",
        value: |report| Some(report.path.clone()),
    },
    ReportFact {
        label: "format",
        column: "format",
        json_pointer: "/format",
        value: |report| Some(report.format.to_string()),
    },
    ReportFact {
        label: "architecture",
        column: "architecture",
        json_pointer: "/architecture",
        value: |report| report.architecture.clone(),
    },
    ReportFact {
        label: "skipped architectures",
        column: "skipped_architectures",
        json_pointer: "/skipped_architectures",
        value: |report| listed(&report.skipped_architectures),
    },
    ReportFact {
        label: "fingerprint",
        column: "fingerprint",
        json_pointer: "/fingerprint",
        value: |report| Some(report.fingerprint.clone()),
    },
    ReportFact {
        label: "analysis",
        column: "analysis_id",
        json_pointer: "/analysis_id",
        value: |report| report.analysis_id.map(|id| id.to_string()),
    },
    ReportFact {
        label: "sections",
        column: "sections",
        json_pointer: "/sections",
        value: |report| Some(report.sections.to_string()),
    },
    ReportFact {
        label: "imports",
        column: "imports",
        json_pointer: "/imports",
        value: |report| Some(report.imports.to_string()),
    },
    ReportFact {
        label: "entry points",
        column: "entry_points",
        json_pointer: "/entry_points",
        value: |report| Some(report.entry_points.to_string()),
    },
    ReportFact {
        label: "calls",
        column: "calls",
        json_pointer: "/calls",
        value: |report| Some(report.calls.to_string()),
    },
    ReportFact {
        label: "relocations",
        column: "relocations",
        json_pointer: "/relocations",
        value: |report| Some(report.relocations.to_string()),
    },
    ReportFact {
        label: "source mappings",
        column: "source_mappings",
        json_pointer: "/source_mappings",
        value: |report| Some(report.source_mappings.to_string()),
    },
    ReportFact {
        label: "data segments",
        column: "data_segments",
        json_pointer: "/data_segments",
        value: |report| Some(report.data_segments.to_string()),
    },
];

/// The facts one side of a comparison states, under that side's prefix.
macro_rules! side_facts {
    ($side:ident) => {
        [
            ReportFact {
                label: stringify!($side),
                column: concat!(stringify!($side), "_path"),
                json_pointer: concat!("/", stringify!($side), "/path"),
                value: |report| Some(report.$side.path.clone()),
            },
            ReportFact {
                label: concat!(stringify!($side), " format"),
                column: concat!(stringify!($side), "_format"),
                json_pointer: concat!("/", stringify!($side), "/format"),
                value: |report| Some(report.$side.format.to_string()),
            },
            ReportFact {
                label: concat!(stringify!($side), " fingerprint"),
                column: concat!(stringify!($side), "_fingerprint"),
                json_pointer: concat!("/", stringify!($side), "/fingerprint"),
                value: |report| Some(report.$side.fingerprint.clone()),
            },
            ReportFact {
                label: concat!(stringify!($side), " architecture"),
                column: concat!(stringify!($side), "_architecture"),
                json_pointer: concat!("/", stringify!($side), "/architecture"),
                value: |report| report.$side.architecture.clone(),
            },
            ReportFact {
                label: concat!(stringify!($side), " skipped architectures"),
                column: concat!(stringify!($side), "_skipped_architectures"),
                json_pointer: concat!("/", stringify!($side), "/skipped_architectures"),
                value: |report| listed(&report.$side.skipped_architectures),
            },
            ReportFact {
                label: concat!(stringify!($side), " build variant"),
                column: concat!(stringify!($side), "_build_variant_manifest_path"),
                json_pointer: concat!("/", stringify!($side), "/build_variant/manifest_path"),
                value: |report| build_variant(&report.$side, |variant| &variant.manifest_path),
            },
            ReportFact {
                label: concat!(stringify!($side), " build variant digest"),
                column: concat!(stringify!($side), "_build_variant_fingerprint"),
                json_pointer: concat!("/", stringify!($side), "/build_variant/fingerprint"),
                value: |report| build_variant(&report.$side, |variant| &variant.fingerprint),
            },
        ]
    };
}

/// One field of a side's build-variant evidence, when it was supplied.
fn build_variant(
    side: &ComparisonArtifact,
    field: fn(&super::ComparisonBuildVariant) -> &String,
) -> Option<String> {
    side.build_variant
        .as_ref()
        .map(|variant| field(variant).clone())
}

const BEFORE_FACTS: [ReportFact<ArtifactComparisonReport>; 7] = side_facts!(before);
const AFTER_FACTS: [ReportFact<ArtifactComparisonReport>; 7] = side_facts!(after);

/// The scalar facts of one comparison, in text order.
pub(in crate::artifact) const COMPARISON_FACTS: &[ReportFact<ArtifactComparisonReport>] = &[
    BEFORE_FACTS[0],
    BEFORE_FACTS[1],
    BEFORE_FACTS[2],
    BEFORE_FACTS[3],
    BEFORE_FACTS[4],
    BEFORE_FACTS[5],
    BEFORE_FACTS[6],
    AFTER_FACTS[0],
    AFTER_FACTS[1],
    AFTER_FACTS[2],
    AFTER_FACTS[3],
    AFTER_FACTS[4],
    AFTER_FACTS[5],
    AFTER_FACTS[6],
    ReportFact {
        label: "symbols added",
        column: "symbols_added",
        json_pointer: "/symbol_changes/added",
        value: |report| Some(report.symbol_changes.added.to_string()),
    },
    ReportFact {
        label: "symbols removed",
        column: "symbols_removed",
        json_pointer: "/symbol_changes/removed",
        value: |report| Some(report.symbol_changes.removed.to_string()),
    },
    ReportFact {
        label: "named symbols modified",
        column: "modified_named_symbols",
        json_pointer: "/symbol_changes/modified_named_symbols",
        value: |report| Some(report.symbol_changes.modified_named_symbols.to_string()),
    },
];
