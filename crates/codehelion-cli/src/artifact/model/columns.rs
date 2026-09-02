//! The artifact and comparison CSV column schemas.

/// Every artifact CSV column, in the order they are written.
///
/// The CSV is one union table discriminated by `record_type`. A column is
/// named for exactly one quantity: a record that has no such quantity leaves
/// it empty rather than borrowing a neighbouring column, and a quantity the
/// text or JSON rendering states has a column of its own. Columns are only
/// ever appended, so a consumer reading by position keeps reading the same
/// value after a release adds one.
pub(in crate::artifact) const ARTIFACT_CSV_HEADER: &[&str] = &[
    "record_type",
    "path",
    "format",
    "kind",
    "fingerprint",
    "name",
    "offset",
    "size",
    "duplicated_bytes",
    "retained_bytes",
    "dead_code_status",
    "observed_bytes",
    "source_run",
    "mappings",
    "mapped_symbols",
    "unmapped_symbols",
    "upper_bound_savings_bytes",
    "estimated_refactor_savings_bytes",
    "verified_savings_bytes",
    "origin_build_variant_fingerprint",
    "instantiations",
    "translation_units",
    "source_build_variant_fingerprint",
    "artifact_build_variant_fingerprint",
    "mapping_confidence",
    "clone_confidence",
    "model_confidence",
    "savings_confidence",
    "model_schema_version",
    "estimate_assumptions_json",
    "section",
    "executable",
    "module",
    "duplicated_bytes_normalized",
    "estimated_duplicated_bytes",
    "attribution_basis",
    "shared_dependency_bytes",
    "code_section_bytes",
    "data_segment_bytes",
    "artifact_symbols",
    "definition_path_count",
    "members",
    "attributed_noncanonical_members",
    "assumption_scope",
    "assumption",
    "max_input_bytes",
    "worker_timeout_seconds",
    "worker_memory_limit_bytes",
    "source_map_uri",
    "source_map_local_path",
    "source_map_sources",
    "duplicated_data_bytes",
    "containing_symbols",
    "containing_symbol_bytes",
    "emitted_bodies",
    "max_debug_derived_items",
];

/// The columns one kind of record in the artifact CSV carries.
///
/// A record fills a subset of one wide row, and which subset was written down
/// nowhere: a reader could only find out by running the tool, and a writer
/// could start filling a column meant for something else without anything
/// saying so. This is the one description of that, checked against what the
/// writers actually produce.
#[cfg(test)]
pub(in crate::artifact) struct RecordColumns {
    /// The `record_type` value the record is written under.
    pub(in crate::artifact) record_type: &'static str,
    /// Columns the record carries beyond [`EVERY_RECORD`].
    pub(in crate::artifact) columns: &'static [usize],
}

/// Columns every record carries, whatever kind it is: what it is, which
/// artifact it is about, and what format that artifact was read as.
#[cfg(test)]
pub(in crate::artifact) const EVERY_RECORD: &[usize] =
    &[column::RECORD_TYPE, column::PATH, column::FORMAT];

/// What each kind of record carries.
///
/// Ordered as `render_csv` writes them. A record that fills a column absent
/// from its entry fails the check that reads this, so a field added to a
/// record has to say which column carries it before it can appear — which is
/// also where a reader looks to find out what a record type means.
#[cfg(test)]
pub(in crate::artifact) const RECORD_COLUMNS: &[RecordColumns] = &[
    RecordColumns {
        record_type: "summary",
        columns: &[
            column::FINGERPRINT,
            column::OBSERVED_BYTES,
            column::DUPLICATED_BYTES,
            column::DUPLICATED_BYTES_NORMALIZED,
            column::RETAINED_BYTES,
            column::SHARED_DEPENDENCY_BYTES,
            column::DUPLICATED_DATA_BYTES,
            column::UPPER_BOUND_SAVINGS_BYTES,
            column::ESTIMATED_REFACTOR_SAVINGS_BYTES,
            column::VERIFIED_SAVINGS_BYTES,
            column::SOURCE_RUN,
            column::MAPPINGS,
            column::MAPPED_SYMBOLS,
            column::UNMAPPED_SYMBOLS,
            column::CODE_SECTION_BYTES,
            column::DATA_SEGMENT_BYTES,
            column::CLONE_CONFIDENCE,
            column::SAVINGS_CONFIDENCE,
            column::ARTIFACT_SYMBOLS,
        ],
    },
    RecordColumns {
        record_type: "build-variant",
        columns: &[column::FINGERPRINT, column::NAME],
    },
    RecordColumns {
        record_type: "containment",
        columns: &[
            column::MAX_INPUT_BYTES,
            column::WORKER_TIMEOUT_SECONDS,
            column::WORKER_MEMORY_LIMIT_BYTES,
            column::MAX_DEBUG_DERIVED_ITEMS,
        ],
    },
    RecordColumns {
        record_type: "archive-member",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::OFFSET,
            column::SIZE,
            column::DEAD_CODE_STATUS,
        ],
    },
    RecordColumns {
        record_type: "source-map",
        columns: &[
            column::KIND,
            column::SOURCE_MAP_URI,
            column::SOURCE_MAP_LOCAL_PATH,
            column::SOURCE_MAP_SOURCES,
        ],
    },
    RecordColumns {
        record_type: "section",
        columns: &[
            column::KIND,
            column::NAME,
            column::OFFSET,
            column::SIZE,
            column::EXECUTABLE,
        ],
    },
    RecordColumns {
        record_type: "import",
        columns: &[column::KIND, column::NAME, column::MODULE],
    },
    RecordColumns {
        record_type: "relocation",
        columns: &[column::KIND, column::NAME, column::OFFSET, column::SECTION],
    },
    RecordColumns {
        record_type: "data-segment",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::OFFSET,
            column::SIZE,
            column::SECTION,
        ],
    },
    RecordColumns {
        record_type: "duplicate-group",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::DUPLICATED_BYTES,
            column::MEMBERS,
        ],
    },
    RecordColumns {
        record_type: "duplicate-member",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::OFFSET,
            column::SIZE,
        ],
    },
    RecordColumns {
        record_type: "dead-code",
        columns: &[column::FINGERPRINT, column::DEAD_CODE_STATUS],
    },
    RecordColumns {
        record_type: "retained-size",
        columns: &[column::FINGERPRINT, column::RETAINED_BYTES],
    },
    RecordColumns {
        record_type: "clone-group-attribution",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::DUPLICATED_BYTES,
            column::ESTIMATED_DUPLICATED_BYTES,
            column::CONTAINING_SYMBOLS,
            column::CONTAINING_SYMBOL_BYTES,
            column::MEMBERS,
            column::ATTRIBUTED_NONCANONICAL_MEMBERS,
            column::SOURCE_BUILD_VARIANT_FINGERPRINT,
            column::CLONE_CONFIDENCE,
            column::ATTRIBUTION_BASIS,
        ],
    },
    RecordColumns {
        record_type: "multiply-emitted-unit",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::EMITTED_BODIES,
            column::SOURCE_BUILD_VARIANT_FINGERPRINT,
            column::MAPPING_CONFIDENCE,
        ],
    },
    RecordColumns {
        record_type: "clone-group-savings",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::DUPLICATED_BYTES,
            column::ESTIMATED_DUPLICATED_BYTES,
            column::ATTRIBUTION_BASIS,
            column::ESTIMATED_REFACTOR_SAVINGS_BYTES,
            column::SOURCE_BUILD_VARIANT_FINGERPRINT,
            column::ARTIFACT_BUILD_VARIANT_FINGERPRINT,
            column::MAPPING_CONFIDENCE,
            column::CLONE_CONFIDENCE,
            column::MODEL_CONFIDENCE,
            column::SAVINGS_CONFIDENCE,
            column::MODEL_SCHEMA_VERSION,
            column::ESTIMATE_ASSUMPTIONS_JSON,
        ],
    },
    RecordColumns {
        record_type: "generic-origin",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::DUPLICATED_BYTES,
            column::RETAINED_BYTES,
            column::ORIGIN_BUILD_VARIANT_FINGERPRINT,
            column::INSTANTIATIONS,
            column::TRANSLATION_UNITS,
            column::ARTIFACT_SYMBOLS,
        ],
    },
    RecordColumns {
        record_type: "generic-specialization",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::ORIGIN_BUILD_VARIANT_FINGERPRINT,
            column::INSTANTIATIONS,
            column::TRANSLATION_UNITS,
            column::ARTIFACT_SYMBOLS,
        ],
    },
    RecordColumns {
        record_type: "macro-origin",
        columns: &[
            column::KIND,
            column::FINGERPRINT,
            column::NAME,
            column::SIZE,
            column::ORIGIN_BUILD_VARIANT_FINGERPRINT,
            column::ARTIFACT_SYMBOLS,
            column::DEFINITION_PATH_COUNT,
        ],
    },
    RecordColumns {
        record_type: "assumption",
        columns: &[column::ASSUMPTION_SCOPE, column::ASSUMPTION],
    },
];

// Columns are only ever appended, so the published width never shrinks.
const _: () = assert!(ARTIFACT_CSV_HEADER.len() >= crate::artifact::ARTIFACT_CSV_COLUMNS);

/// Column positions in [`ARTIFACT_CSV_HEADER`], named as the header names them.
pub(in crate::artifact) mod column {
    pub(in crate::artifact) const RECORD_TYPE: usize = 0;
    pub(in crate::artifact) const PATH: usize = 1;
    pub(in crate::artifact) const FORMAT: usize = 2;
    pub(in crate::artifact) const KIND: usize = 3;
    pub(in crate::artifact) const FINGERPRINT: usize = 4;
    pub(in crate::artifact) const NAME: usize = 5;
    pub(in crate::artifact) const OFFSET: usize = 6;
    pub(in crate::artifact) const SIZE: usize = 7;
    pub(in crate::artifact) const DUPLICATED_BYTES: usize = 8;
    pub(in crate::artifact) const RETAINED_BYTES: usize = 9;
    pub(in crate::artifact) const DEAD_CODE_STATUS: usize = 10;
    pub(in crate::artifact) const OBSERVED_BYTES: usize = 11;
    pub(in crate::artifact) const SOURCE_RUN: usize = 12;
    pub(in crate::artifact) const MAPPINGS: usize = 13;
    pub(in crate::artifact) const MAPPED_SYMBOLS: usize = 14;
    pub(in crate::artifact) const UNMAPPED_SYMBOLS: usize = 15;
    pub(in crate::artifact) const UPPER_BOUND_SAVINGS_BYTES: usize = 16;
    pub(in crate::artifact) const ESTIMATED_REFACTOR_SAVINGS_BYTES: usize = 17;
    pub(in crate::artifact) const VERIFIED_SAVINGS_BYTES: usize = 18;
    pub(in crate::artifact) const ORIGIN_BUILD_VARIANT_FINGERPRINT: usize = 19;
    pub(in crate::artifact) const INSTANTIATIONS: usize = 20;
    pub(in crate::artifact) const TRANSLATION_UNITS: usize = 21;
    pub(in crate::artifact) const SOURCE_BUILD_VARIANT_FINGERPRINT: usize = 22;
    pub(in crate::artifact) const ARTIFACT_BUILD_VARIANT_FINGERPRINT: usize = 23;
    pub(in crate::artifact) const MAPPING_CONFIDENCE: usize = 24;
    pub(in crate::artifact) const CLONE_CONFIDENCE: usize = 25;
    pub(in crate::artifact) const MODEL_CONFIDENCE: usize = 26;
    pub(in crate::artifact) const SAVINGS_CONFIDENCE: usize = 27;
    pub(in crate::artifact) const MODEL_SCHEMA_VERSION: usize = 28;
    pub(in crate::artifact) const ESTIMATE_ASSUMPTIONS_JSON: usize = 29;
    pub(in crate::artifact) const SECTION: usize = 30;
    pub(in crate::artifact) const EXECUTABLE: usize = 31;
    pub(in crate::artifact) const MODULE: usize = 32;
    pub(in crate::artifact) const DUPLICATED_BYTES_NORMALIZED: usize = 33;
    pub(in crate::artifact) const ESTIMATED_DUPLICATED_BYTES: usize = 34;
    pub(in crate::artifact) const ATTRIBUTION_BASIS: usize = 35;
    pub(in crate::artifact) const SHARED_DEPENDENCY_BYTES: usize = 36;
    pub(in crate::artifact) const CODE_SECTION_BYTES: usize = 37;
    pub(in crate::artifact) const DATA_SEGMENT_BYTES: usize = 38;
    pub(in crate::artifact) const ARTIFACT_SYMBOLS: usize = 39;
    pub(in crate::artifact) const DEFINITION_PATH_COUNT: usize = 40;
    pub(in crate::artifact) const MEMBERS: usize = 41;
    pub(in crate::artifact) const ATTRIBUTED_NONCANONICAL_MEMBERS: usize = 42;
    pub(in crate::artifact) const ASSUMPTION_SCOPE: usize = 43;
    pub(in crate::artifact) const ASSUMPTION: usize = 44;
    pub(in crate::artifact) const MAX_INPUT_BYTES: usize = 45;
    pub(in crate::artifact) const WORKER_TIMEOUT_SECONDS: usize = 46;
    pub(in crate::artifact) const WORKER_MEMORY_LIMIT_BYTES: usize = 47;
    pub(in crate::artifact) const SOURCE_MAP_URI: usize = 48;
    pub(in crate::artifact) const SOURCE_MAP_LOCAL_PATH: usize = 49;
    pub(in crate::artifact) const SOURCE_MAP_SOURCES: usize = 50;
    pub(in crate::artifact) const DUPLICATED_DATA_BYTES: usize = 51;
    pub(in crate::artifact) const CONTAINING_SYMBOLS: usize = 52;
    pub(in crate::artifact) const CONTAINING_SYMBOL_BYTES: usize = 53;
    pub(in crate::artifact) const EMITTED_BODIES: usize = 54;
    pub(in crate::artifact) const MAX_DEBUG_DERIVED_ITEMS: usize = 55;
}

/// Every comparison CSV column, in the order they are written, under the same
/// union-table rules as [`ARTIFACT_CSV_HEADER`].
pub(in crate::artifact) const COMPARE_CSV_HEADER: &[&str] = &[
    "record_type",
    "before_path",
    "after_path",
    "before_format",
    "after_format",
    "before_fingerprint",
    "after_fingerprint",
    "observed_size_reduction_bytes",
    "duplicated_code_delta_bytes",
    "duplicated_data_delta_bytes",
    "estimated_refactor_savings_bytes",
    "verified_savings_bytes",
    "source_run",
    "clone_group_fingerprint",
    "change_kind",
    "name",
    "fingerprint",
    "symbol_size_delta_bytes",
    "duplicated_bytes_delta",
    "members_delta",
    "warning",
    "absolute_error_bytes",
    "relative_error",
    "before_code_section_bytes",
    "after_code_section_bytes",
    "code_section_delta_bytes",
    "before_data_segment_bytes",
    "after_data_segment_bytes",
    "data_segment_delta_bytes",
    "assumption_scope",
    "assumption",
    "max_input_bytes",
    "worker_timeout_seconds",
    "worker_memory_limit_bytes",
    "artifact_analysis_id",
    "matching_analyses",
    "calibration_record",
];

/// Column positions in [`COMPARE_CSV_HEADER`].
pub(in crate::artifact) mod compare_column {
    pub(in crate::artifact) const RECORD_TYPE: usize = 0;
    pub(in crate::artifact) const BEFORE_PATH: usize = 1;
    pub(in crate::artifact) const AFTER_PATH: usize = 2;
    pub(in crate::artifact) const BEFORE_FORMAT: usize = 3;
    pub(in crate::artifact) const AFTER_FORMAT: usize = 4;
    pub(in crate::artifact) const BEFORE_FINGERPRINT: usize = 5;
    pub(in crate::artifact) const AFTER_FINGERPRINT: usize = 6;
    pub(in crate::artifact) const OBSERVED_SIZE_REDUCTION_BYTES: usize = 7;
    pub(in crate::artifact) const DUPLICATED_CODE_DELTA_BYTES: usize = 8;
    pub(in crate::artifact) const DUPLICATED_DATA_DELTA_BYTES: usize = 9;
    pub(in crate::artifact) const ESTIMATED_REFACTOR_SAVINGS_BYTES: usize = 10;
    pub(in crate::artifact) const VERIFIED_SAVINGS_BYTES: usize = 11;
    pub(in crate::artifact) const SOURCE_RUN: usize = 12;
    pub(in crate::artifact) const CLONE_GROUP_FINGERPRINT: usize = 13;
    pub(in crate::artifact) const CHANGE_KIND: usize = 14;
    pub(in crate::artifact) const NAME: usize = 15;
    pub(in crate::artifact) const FINGERPRINT: usize = 16;
    pub(in crate::artifact) const SYMBOL_SIZE_DELTA_BYTES: usize = 17;
    pub(in crate::artifact) const DUPLICATED_BYTES_DELTA: usize = 18;
    pub(in crate::artifact) const MEMBERS_DELTA: usize = 19;
    pub(in crate::artifact) const WARNING: usize = 20;
    pub(in crate::artifact) const ABSOLUTE_ERROR_BYTES: usize = 21;
    pub(in crate::artifact) const RELATIVE_ERROR: usize = 22;
    pub(in crate::artifact) const BEFORE_CODE_SECTION_BYTES: usize = 23;
    pub(in crate::artifact) const AFTER_CODE_SECTION_BYTES: usize = 24;
    pub(in crate::artifact) const CODE_SECTION_DELTA_BYTES: usize = 25;
    pub(in crate::artifact) const BEFORE_DATA_SEGMENT_BYTES: usize = 26;
    pub(in crate::artifact) const AFTER_DATA_SEGMENT_BYTES: usize = 27;
    pub(in crate::artifact) const DATA_SEGMENT_DELTA_BYTES: usize = 28;
    pub(in crate::artifact) const ASSUMPTION_SCOPE: usize = 29;
    pub(in crate::artifact) const ASSUMPTION: usize = 30;
    pub(in crate::artifact) const MAX_INPUT_BYTES: usize = 31;
    pub(in crate::artifact) const WORKER_TIMEOUT_SECONDS: usize = 32;
    pub(in crate::artifact) const WORKER_MEMORY_LIMIT_BYTES: usize = 33;
    pub(in crate::artifact) const ARTIFACT_ANALYSIS_ID: usize = 34;
    pub(in crate::artifact) const MATCHING_ANALYSES: usize = 35;
    pub(in crate::artifact) const CALIBRATION_RECORD: usize = 36;
}
