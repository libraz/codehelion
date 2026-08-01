//! Schema definition for the single pre-release v1 baseline.
//!
//! The schema covers every scan entity: `ScanRun`, `BuildVariant`,
//! `SourceUnit`, `Fragment`, `Fingerprint`, `CloneGroup`, `Finding`,
//! `Suppression`, `Artifact`, `ArtifactSymbol`,
//! `SourceArtifactMapping` and `DetectorVersion`, plus the candidate-index
//! feature tables `FeatureFingerprint`, `FeatureOccurrence` and `UnitFeature`,
//! the per-group `CloneGroupSimilarity` breakdown, and the per-run report
//! tables `RunSummary`, `RunFunnelStage`, `RunFunnelDrop` and
//! `RunUnusedSuppression`, which hold what a report says about a run beyond
//! the findings it lists, and the `compiler_*` tables holding what a compiler
//! helper answered about each unit — including the units it could not answer
//! for, which is an outcome rather than a gap.
//! The artifact tables are created empty in this release — the schema is the
//! contract, population comes with the features that need them.
//!
//! Invariants enforced at the schema level:
//!
//! - Stable identifiers are 16-byte fingerprint BLOBs; file paths, line
//!   numbers and offsets appear only as non-authoritative anchor columns and
//!   never in a UNIQUE or key role.
//! - Feature hashes are candidate-index keys, not stable identifiers, and
//!   live in their own tables. They carry a `feature_schema_version` (never a
//!   `normalization_version`) in their dedup key, so hashes from incompatible
//!   feature recipes never merge, and they never mix into `fingerprint`.
//! - Every fingerprint row carries its full analysis context (hash
//!   algorithm, normalization version, frontend version, mode, language,
//!   build variant) inside its UNIQUE constraint, so equal hashes produced
//!   under incompatible rules never merge. Group fingerprints span languages
//!   and frontends; their rows store the empty string for those two columns
//!   (not NULL, which `SQLite` treats as always-distinct under UNIQUE).
//! - `scan_run.build_variant_id` is NOT NULL: results without a variant
//!   cannot exist.
//! - A build variant records what it was, not only the hash it is known by:
//!   what a compiler was told lives in `build_variant_setting`, one row per
//!   value, in the order it was given. A row written before variants were
//!   described reads as NULL there, which is not the same as a build that was
//!   resolved and said nothing.
//! - `compiler_helper.restarts` counts how often a run had to restart the
//!   helper. NULL is a run that did not count; zero is a run whose helper
//!   survived the whole tree.
//! - `compiler_helper_execution` holds what a helper said it would run when
//!   permitted, which is not what the run permitted it: the permission is part
//!   of the build variant, because results depend on it.
//! - Savings and confidence live in separate columns; there is no single
//!   collapsed score column.
//!
//! Before the first release, schema fragments are assembled into one baseline.
//! `schema_meta` records which baseline a database holds. A database from any
//! other layout is rejected and recreated without conversion.

use rusqlite::Connection;

use crate::StoreError;

/// The one unreleased development schema baseline this build reads.
///
/// A database recorded under another one is rejected rather than migrated.
/// Nothing is lost by that: the audit database holds the latest scan, which
/// re-running the scan reproduces.
pub const SCHEMA_VERSION: i64 = 11;

/// Full pre-release database layout. Existing development databases are not
/// transformed; create a fresh database when this contract changes.
const BASELINE_SQL: &str = r#"
CREATE TABLE artifact (
    id                 INTEGER PRIMARY KEY,
    scan_run_id        INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    build_variant_id   INTEGER NOT NULL REFERENCES build_variant (id),
    format             TEXT NOT NULL CHECK (format IN ('wasm', 'elf', 'macho', 'pe-coff', 'archive')),
    path               TEXT NOT NULL,
    total_size_bytes   INTEGER NOT NULL,
    code_section_bytes INTEGER,
    data_section_bytes INTEGER,
    content_hash       TEXT NOT NULL
) STRICT;
CREATE TABLE artifact_analysis (
    id                INTEGER PRIMARY KEY,
    schema_version    TEXT NOT NULL,
    path              TEXT NOT NULL,
    format            TEXT NOT NULL CHECK (format IN ('wasm', 'elf', 'macho', 'pe-coff', 'archive')),
    content_fingerprint BLOB NOT NULL CHECK (length(content_fingerprint) = 16),
    observed_bytes    INTEGER NOT NULL,
    started_at        TEXT NOT NULL,
    finished_at       TEXT NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('completed'))
, ir_json TEXT NOT NULL DEFAULT '{}', build_variant_manifest_path TEXT, build_variant_fingerprint BLOB
        CHECK (build_variant_fingerprint IS NULL OR length(build_variant_fingerprint) = 16)) STRICT;
CREATE TABLE artifact_analysis_clone_group_savings (
    id                              INTEGER PRIMARY KEY,
    schema_version                  TEXT NOT NULL,
    artifact_analysis_id            INTEGER NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    source_scan_run_id              INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE RESTRICT,
    clone_group_fingerprint         BLOB NOT NULL CHECK (length(clone_group_fingerprint) = 16),
    source_build_variant_fingerprint BLOB NOT NULL CHECK (length(source_build_variant_fingerprint) = 16),
    artifact_build_variant_fingerprint BLOB NOT NULL CHECK (length(artifact_build_variant_fingerprint) = 16),
    duplicated_bytes                INTEGER NOT NULL CHECK (duplicated_bytes >= 0),
    estimated_refactor_savings_bytes INTEGER NOT NULL,
    mapping_confidence              TEXT NOT NULL CHECK (mapping_confidence IN ('high', 'medium', 'low', 'unavailable')),
    clone_confidence                REAL NOT NULL,
    model_confidence                TEXT NOT NULL CHECK (model_confidence IN ('high', 'medium', 'low', 'unavailable')),
    savings_confidence              TEXT NOT NULL CHECK (savings_confidence IN ('high', 'medium', 'low', 'unavailable')),
    model_schema_version            TEXT NOT NULL,
    assumptions_json                TEXT NOT NULL,
    UNIQUE (artifact_analysis_id, source_scan_run_id, clone_group_fingerprint,
            source_build_variant_fingerprint, artifact_build_variant_fingerprint)
) STRICT;
CREATE TABLE artifact_analysis_correlation (
    artifact_analysis_id       INTEGER PRIMARY KEY REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    schema_version             TEXT NOT NULL,
    source_scan_run_id         INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE RESTRICT,
    mapping_count              INTEGER NOT NULL CHECK (mapping_count >= 0),
    artifact_symbol_count      INTEGER NOT NULL CHECK (artifact_symbol_count >= 0),
    mapped_symbol_count        INTEGER NOT NULL
        CHECK (mapped_symbol_count >= 0 AND mapped_symbol_count <= artifact_symbol_count),
    artifact_symbol_bytes      INTEGER NOT NULL CHECK (artifact_symbol_bytes >= 0),
    mapped_symbol_bytes        INTEGER NOT NULL
        CHECK (mapped_symbol_bytes >= 0 AND mapped_symbol_bytes <= artifact_symbol_bytes)
) STRICT;
CREATE TABLE artifact_analysis_savings_calibration (
    id                              INTEGER PRIMARY KEY,
    schema_version                  TEXT NOT NULL,
    artifact_analysis_id            INTEGER NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    source_scan_run_id              INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE RESTRICT,
    clone_group_fingerprint         BLOB NOT NULL CHECK (length(clone_group_fingerprint) = 16),
    source_build_variant_fingerprint BLOB NOT NULL CHECK (length(source_build_variant_fingerprint) = 16),
    before_artifact_build_variant_fingerprint BLOB NOT NULL CHECK (length(before_artifact_build_variant_fingerprint) = 16),
    after_artifact_fingerprint      BLOB NOT NULL CHECK (length(after_artifact_fingerprint) = 16),
    after_artifact_build_variant_fingerprint BLOB NOT NULL CHECK (length(after_artifact_build_variant_fingerprint) = 16),
    estimated_refactor_savings_bytes INTEGER NOT NULL,
    verified_savings_bytes          INTEGER NOT NULL,
    absolute_error_bytes            INTEGER NOT NULL CHECK (absolute_error_bytes >= 0),
    relative_error                  REAL,
    recorded_at                     TEXT NOT NULL,
    UNIQUE (artifact_analysis_id, source_scan_run_id, clone_group_fingerprint,
            source_build_variant_fingerprint, before_artifact_build_variant_fingerprint,
            after_artifact_fingerprint, after_artifact_build_variant_fingerprint)
) STRICT;
CREATE TABLE "artifact_analysis_source_mapping" (
    id                          INTEGER PRIMARY KEY,
    schema_version              TEXT NOT NULL,
    artifact_analysis_id        INTEGER NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    artifact_symbol_fingerprint BLOB NOT NULL CHECK (length(artifact_symbol_fingerprint) = 16),
    source_kind                 TEXT NOT NULL CHECK (source_kind IN ('unit', 'fragment')),
    source_fingerprint          BLOB NOT NULL CHECK (length(source_fingerprint) = 16),
    source_instance_fingerprint BLOB NOT NULL CHECK (length(source_instance_fingerprint) = 16),
    evidence_json               TEXT NOT NULL,
    mapping_confidence          TEXT NOT NULL CHECK (mapping_confidence IN ('exact', 'strong', 'weak', 'ambiguous')),
    attributed_bytes            INTEGER,
    build_variant_fingerprint   BLOB NOT NULL CHECK (length(build_variant_fingerprint) = 16),
    source_build_variant_fingerprint BLOB
        CHECK (source_build_variant_fingerprint IS NULL OR length(source_build_variant_fingerprint) = 16),
    CHECK (attributed_bytes IS NULL OR attributed_bytes >= 0),
    UNIQUE (
        schema_version, artifact_analysis_id, artifact_symbol_fingerprint,
        source_kind, source_fingerprint, source_instance_fingerprint, evidence_json
    )
) STRICT;
CREATE TABLE artifact_analysis_symbol (
    analysis_id             INTEGER NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    ordinal                 INTEGER NOT NULL,
    fingerprint             BLOB NOT NULL CHECK (length(fingerprint) = 16),
    name                    TEXT,
    section_index           INTEGER,
    offset                  INTEGER NOT NULL,
    size_bytes              INTEGER NOT NULL,
    size_inferred           INTEGER NOT NULL CHECK (size_inferred IN (0, 1)),
    code_fingerprint        BLOB NOT NULL CHECK (length(code_fingerprint) = 16),
    normalization_version   TEXT,
    normalization_fingerprint BLOB, exported INTEGER NOT NULL DEFAULT 0 CHECK (exported IN (0, 1)),
    PRIMARY KEY (analysis_id, ordinal),
    CHECK (normalization_fingerprint IS NULL OR length(normalization_fingerprint) = 16)
) STRICT;
CREATE TABLE "artifact_analysis_unmapped_source" (
    artifact_analysis_id      INTEGER NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    source_kind               TEXT NOT NULL CHECK (source_kind IN ('unit', 'fragment')),
    source_fingerprint        BLOB NOT NULL CHECK (length(source_fingerprint) = 16),
    source_instance_fingerprint BLOB NOT NULL CHECK (length(source_instance_fingerprint) = 16),
    reason                    TEXT NOT NULL CHECK (reason IN
                                 ('no_artifact_evidence', 'dead_code', 'inlined_away', 'lto_absorbed',
                                  'not_compiled_for_variant', 'evidence_conflict')),
    source_build_variant_fingerprint BLOB
        CHECK (source_build_variant_fingerprint IS NULL OR length(source_build_variant_fingerprint) = 16),
    PRIMARY KEY (artifact_analysis_id, source_kind, source_fingerprint, source_instance_fingerprint)
) STRICT;
CREATE TABLE artifact_analysis_unmapped_symbol (
    artifact_analysis_id        INTEGER NOT NULL REFERENCES artifact_analysis (id) ON DELETE CASCADE,
    artifact_symbol_fingerprint BLOB NOT NULL CHECK (length(artifact_symbol_fingerprint) = 16),
    reason                      TEXT NOT NULL CHECK (reason IN
                                    ('debug_info_missing', 'stripped', 'demangle_failed',
                                     'outside_source_scope', 'evidence_conflict')),
    PRIMARY KEY (artifact_analysis_id, artifact_symbol_fingerprint)
) STRICT;
CREATE TABLE artifact_symbol (
    id             INTEGER PRIMARY KEY,
    artifact_id    INTEGER NOT NULL REFERENCES artifact (id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    demangled_name TEXT,
    section        TEXT,
    symbol_kind    TEXT NOT NULL CHECK (symbol_kind IN ('function', 'data')),
    offset         INTEGER,
    size_bytes     INTEGER NOT NULL,
    code_hash      TEXT,
    is_exported    INTEGER NOT NULL CHECK (is_exported IN (0, 1))
) STRICT;
CREATE TABLE "build_variant" (
    id                    INTEGER PRIMARY KEY,
    variant_fingerprint   TEXT NOT NULL UNIQUE,
    canonical             TEXT NOT NULL,
    analysis_mode         TEXT NOT NULL CHECK (analysis_mode IN ('fast', 'structural', 'semantic')),
    normalization_version INTEGER NOT NULL,
    languages             TEXT,
    header_language       TEXT
        CHECK (header_language IS NULL OR header_language IN ('rust', 'c', 'cpp', '')),
    build_language        TEXT
) STRICT;
CREATE TABLE "build_variant_setting" (
    build_variant_id INTEGER NOT NULL REFERENCES build_variant (id) ON DELETE CASCADE,
    language         TEXT NOT NULL,
    name             TEXT NOT NULL,
    position         INTEGER NOT NULL,
    value            TEXT NOT NULL,
    PRIMARY KEY (build_variant_id, language, name, position)
) STRICT;
CREATE TABLE "clone_group" (
    id                   INTEGER PRIMARY KEY,
    scan_run_id          INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    group_fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    clone_type           TEXT NOT NULL CHECK (clone_type IN ('type-1', 'type-2', 'type-3', 'restricted-semantic')),
    member_count         INTEGER NOT NULL,
    score                REAL NOT NULL,
    entropy_bits         REAL NOT NULL,
    suppress_reason      TEXT CHECK (suppress_reason IN ('low-entropy', 'high-frequency')),
    boilerplate          TEXT CHECK (boilerplate IN ('trivial-body', 'forwarding', 'macro-repetition', 'guarded-dispatch', 'configured-answer')),
    member_scope         TEXT NOT NULL DEFAULT 'unit' CHECK (member_scope IN ('unit', 'fragment')),
    test_code            INTEGER NOT NULL DEFAULT 0 CHECK (test_code IN (0, 1)),
    test_code_evidence   TEXT CHECK (test_code_evidence IN ('marker', 'path')),
    split_pair           INTEGER NOT NULL DEFAULT 0 CHECK (split_pair IN (0, 1)),
    width_family         INTEGER NOT NULL DEFAULT 0 CHECK (width_family IN (0, 1))
, statements INTEGER, identifier_jaccard REAL CHECK (identifier_jaccard >= 0 AND identifier_jaccard <= 1)
, has_loop INTEGER CHECK (has_loop IN (0, 1)), has_dynamic_allocation INTEGER CHECK (has_dynamic_allocation IN (0, 1))
, call_count INTEGER CHECK (call_count >= 0)) STRICT;
CREATE TABLE clone_group_member (
    clone_group_id INTEGER NOT NULL REFERENCES clone_group (id) ON DELETE CASCADE,
    fragment_id    INTEGER NOT NULL REFERENCES fragment (id) ON DELETE CASCADE,
    finding_id     BLOB NOT NULL CHECK (length(finding_id) = 16),
    is_canonical   INTEGER NOT NULL CHECK (is_canonical IN (0, 1)),
    boilerplate    TEXT CHECK (boilerplate IN ('trivial-body', 'forwarding', 'macro-repetition', 'guarded-dispatch', 'configured-answer')),
    PRIMARY KEY (clone_group_id, fragment_id)
) STRICT;
CREATE TABLE "clone_group_similarity" (
    clone_group_id  INTEGER PRIMARY KEY REFERENCES clone_group (id) ON DELETE CASCADE,
    weight_version  TEXT NOT NULL,
    lexical         REAL NOT NULL,
    structural      REAL NOT NULL,
    control_flow    REAL,
    type_similarity REAL,
    api             REAL,
    composite       REAL NOT NULL,
    min_pairwise    REAL NOT NULL,
    confidence_band TEXT CHECK (confidence_band IN ('high', 'medium', 'low'))
) STRICT;
CREATE TABLE compiler_block (
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    block_index           INTEGER NOT NULL,
    length                INTEGER NOT NULL,
    expansion_file        TEXT NOT NULL,
    expansion_start_byte  INTEGER NOT NULL,
    expansion_end_byte    INTEGER NOT NULL,
    expansion_start_line  INTEGER NOT NULL,
    definition_file       TEXT,
    definition_start_byte INTEGER,
    definition_end_byte   INTEGER,
    definition_start_line INTEGER,
    PRIMARY KEY (compiler_unit_id, block_index)
) STRICT;
CREATE TABLE compiler_call (
    id                    INTEGER PRIMARY KEY,
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    resolution            TEXT NOT NULL CHECK (resolution IN
                              ('static', 'dynamic', 'unresolved')),
    target_symbol         TEXT,
    api_name              TEXT,
    expansion_file        TEXT NOT NULL,
    expansion_start_byte  INTEGER NOT NULL,
    expansion_end_byte    INTEGER NOT NULL,
    expansion_start_line  INTEGER NOT NULL,
    definition_file       TEXT,
    definition_start_byte INTEGER,
    definition_end_byte   INTEGER,
    definition_start_line INTEGER,
    UNIQUE (compiler_unit_id, ordinal),
    CHECK ((resolution = 'static') = (target_symbol IS NOT NULL))
) STRICT;
CREATE TABLE compiler_call_candidate (
    compiler_call_id INTEGER NOT NULL REFERENCES compiler_call (id) ON DELETE CASCADE,
    position         INTEGER NOT NULL,
    symbol           TEXT NOT NULL,
    PRIMARY KEY (compiler_call_id, position)
) STRICT;
CREATE TABLE compiler_data_flow (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal          INTEGER NOT NULL,
    source_symbol    TEXT NOT NULL,
    sink_symbol      TEXT NOT NULL,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_edge (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal          INTEGER NOT NULL,
    from_block       INTEGER NOT NULL,
    to_block         INTEGER NOT NULL,
    edge_kind        TEXT NOT NULL CHECK (edge_kind IN
                         ('flow', 'taken', 'not_taken', 'unwind', 'return')),
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_effect (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal          INTEGER NOT NULL,
    effect_kind      TEXT NOT NULL CHECK (effect_kind IN ('write', 'interaction')),
    subject          TEXT NOT NULL,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_expression (
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    type_index            INTEGER NOT NULL,
    expansion_file        TEXT NOT NULL,
    expansion_start_byte  INTEGER NOT NULL,
    expansion_end_byte    INTEGER NOT NULL,
    expansion_start_line  INTEGER NOT NULL,
    definition_file       TEXT,
    definition_start_byte INTEGER,
    definition_end_byte   INTEGER,
    definition_start_line INTEGER,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_helper (
    id              INTEGER PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    restarts         INTEGER
    CHECK (restarts IS NULL OR restarts >= 0),
    UNIQUE (scan_run_id, name, version)
) STRICT;
CREATE TABLE compiler_helper_capability (
    compiler_helper_id INTEGER NOT NULL REFERENCES compiler_helper (id) ON DELETE CASCADE,
    capability         TEXT NOT NULL,
    PRIMARY KEY (compiler_helper_id, capability)
) STRICT;
CREATE TABLE compiler_helper_execution (
    compiler_helper_id INTEGER NOT NULL REFERENCES compiler_helper (id) ON DELETE CASCADE,
    execution          TEXT NOT NULL,
    PRIMARY KEY (compiler_helper_id, execution)
) STRICT;
CREATE TABLE compiler_helper_toolchain (
    compiler_helper_id INTEGER NOT NULL REFERENCES compiler_helper (id) ON DELETE CASCADE,
    toolchain          TEXT NOT NULL,
    PRIMARY KEY (compiler_helper_id, toolchain)
) STRICT;
CREATE TABLE compiler_instantiation (
    id                    INTEGER PRIMARY KEY,
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    definition            TEXT NOT NULL,
    artifact_match_key    TEXT,
    instantiation_key     TEXT NOT NULL,
    expansion_file        TEXT NOT NULL,
    expansion_start_byte  INTEGER NOT NULL,
    expansion_end_byte    INTEGER NOT NULL,
    expansion_start_line  INTEGER NOT NULL,
    definition_file       TEXT,
    definition_start_byte INTEGER,
    definition_end_byte   INTEGER,
    definition_start_line INTEGER,
    definition_end_line   INTEGER,
    UNIQUE (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_instantiation_argument (
    compiler_instantiation_id INTEGER NOT NULL
                                  REFERENCES compiler_instantiation (id) ON DELETE CASCADE,
    position                  INTEGER NOT NULL,
    type_index                INTEGER NOT NULL,
    PRIMARY KEY (compiler_instantiation_id, position)
) STRICT;
CREATE TABLE compiler_semantic_construct (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('source', 'collect', 'reduce', 'propagate_error', 'validate', 'acquire_resource', 'release_resource')),
    fallible_kind TEXT CHECK (fallible_kind IN ('option', 'result')),
    direct_propagation TEXT CHECK (direct_propagation IN ('result_adapter', 'option_adapter')),
    resource_kind TEXT,
    expansion_file TEXT NOT NULL,
    expansion_start_byte INTEGER NOT NULL,
    expansion_end_byte INTEGER NOT NULL,
    expansion_start_line INTEGER NOT NULL,
    definition_file TEXT,
    definition_start_byte INTEGER,
    definition_end_byte INTEGER,
    definition_start_line INTEGER,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_symbol (
    id                    INTEGER PRIMARY KEY,
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    symbol_id             TEXT NOT NULL,
    name                  TEXT NOT NULL,
    symbol_kind           TEXT NOT NULL CHECK (symbol_kind IN
                              ('function', 'type', 'field', 'variant', 'binding',
                               'constant', 'namespace', 'other')),
    type_index            INTEGER,
    external              INTEGER NOT NULL CHECK (external IN (0, 1)),
    expansion_file        TEXT NOT NULL,
    expansion_start_byte  INTEGER NOT NULL,
    expansion_end_byte    INTEGER NOT NULL,
    expansion_start_line  INTEGER NOT NULL,
    definition_file       TEXT,
    definition_start_byte INTEGER,
    definition_end_byte   INTEGER,
    definition_start_line INTEGER,
    UNIQUE (compiler_unit_id, ordinal),
    CHECK ((definition_file IS NULL) = (definition_start_byte IS NULL)
       AND (definition_file IS NULL) = (definition_end_byte IS NULL)
       AND (definition_file IS NULL) = (definition_start_line IS NULL))
) STRICT;
CREATE TABLE compiler_type (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    type_index       INTEGER NOT NULL,
    display          TEXT NOT NULL,
    category         TEXT NOT NULL CHECK (category IN
                         ('integer', 'float', 'boolean', 'character', 'text', 'handle',
                          'sequence', 'mapping', 'tuple', 'record', 'enumeration',
                          'interface', 'callable', 'parameter', 'nothing', 'unresolved')),
    definition       TEXT,
    PRIMARY KEY (compiler_unit_id, type_index)
) STRICT;
CREATE TABLE compiler_type_argument (
    compiler_unit_id INTEGER NOT NULL,
    type_index       INTEGER NOT NULL,
    position         INTEGER NOT NULL,
    argument_index   INTEGER NOT NULL,
    PRIMARY KEY (compiler_unit_id, type_index, position),
    FOREIGN KEY (compiler_unit_id, type_index)
        REFERENCES compiler_type (compiler_unit_id, type_index) ON DELETE CASCADE
) STRICT;
CREATE TABLE compiler_unexpanded_macro (
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    reason                TEXT NOT NULL CHECK (reason IN
                             ('requires_execution', 'unresolved', 'expansion_unavailable')),
    invocation_file       TEXT NOT NULL,
    invocation_start_byte INTEGER NOT NULL,
    invocation_end_byte   INTEGER NOT NULL,
    invocation_start_line INTEGER NOT NULL,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
CREATE TABLE compiler_unit (
    id                 INTEGER PRIMARY KEY,
    scan_run_id        INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    build_variant_id   INTEGER NOT NULL REFERENCES build_variant (id),
    compiler_helper_id INTEGER REFERENCES compiler_helper (id),
    unit_name          TEXT NOT NULL,
    file_path          TEXT NOT NULL,
    variant_key        TEXT NOT NULL,
    schema_version     TEXT,
    unavailable_reason TEXT CHECK (unavailable_reason IN
                           ('requires_execution', 'no_build_information', 'toolchain_mismatch',
                            'helper_timed_out', 'helper_died', 'unreadable_schema',
                            'not_supported')),
    has_cfg            INTEGER NOT NULL CHECK (has_cfg IN (0, 1)),
    effects_computed   INTEGER NOT NULL CHECK (effects_computed IN (0, 1)),
    data_flow_computed INTEGER NOT NULL CHECK (data_flow_computed IN (0, 1)), anchored_at TEXT,
    UNIQUE (scan_run_id, unit_name, file_path, variant_key),
    CHECK ((schema_version IS NULL) <> (unavailable_reason IS NULL)),
    CHECK (unavailable_reason IS NULL
           OR (has_cfg = 0 AND effects_computed = 0 AND data_flow_computed = 0))
) STRICT;
CREATE TABLE cross_language_comparison (
    id                    INTEGER PRIMARY KEY,
    comparison_id         BLOB NOT NULL CHECK (length(comparison_id) = 16),
    policy_version        TEXT NOT NULL,
    root_path             TEXT NOT NULL,
    started_at            TEXT NOT NULL,
    finished_at           TEXT NOT NULL
) STRICT;
CREATE TABLE cross_language_comparison_origin (
    comparison_id              INTEGER NOT NULL REFERENCES cross_language_comparison (id) ON DELETE CASCADE,
    build_variant_fingerprint  TEXT NOT NULL,
    PRIMARY KEY (comparison_id, build_variant_fingerprint)
) STRICT;
CREATE TABLE cross_language_semantic_group (
    id                       INTEGER PRIMARY KEY,
    comparison_id            INTEGER NOT NULL REFERENCES cross_language_comparison (id) ON DELETE CASCADE,
    group_id                 BLOB NOT NULL CHECK (length(group_id) = 16),
    rule_id                  TEXT NOT NULL,
    rule_version             INTEGER NOT NULL,
    semantic_confidence      REAL NOT NULL,
    correspondence_ids_json  TEXT NOT NULL,
    member_count             INTEGER NOT NULL
) STRICT;
CREATE TABLE cross_language_semantic_member (
    group_id                   INTEGER NOT NULL REFERENCES cross_language_semantic_group (id) ON DELETE CASCADE,
    origin_variant_fingerprint TEXT NOT NULL,
    language                   TEXT NOT NULL CHECK (language IN ('rust', 'cpp')),
    file_path                  TEXT NOT NULL,
    start_line                 INTEGER NOT NULL,
    end_line                   INTEGER NOT NULL,
    unit_name                  TEXT,
    graph_schema_version       TEXT NOT NULL,
    graph_json                 TEXT NOT NULL,
    PRIMARY KEY (group_id, origin_variant_fingerprint, file_path, start_line, end_line)
) STRICT;
CREATE TABLE cross_variant_clone_group (
    id                    INTEGER PRIMARY KEY,
    comparison_id         INTEGER NOT NULL REFERENCES cross_variant_comparison (id) ON DELETE CASCADE,
    group_id              BLOB NOT NULL CHECK (length(group_id) = 16),
    clone_type            TEXT NOT NULL CHECK (clone_type IN ('type-1')),
    member_count          INTEGER NOT NULL
) STRICT;
CREATE TABLE cross_variant_clone_member (
    group_id                  INTEGER NOT NULL REFERENCES cross_variant_clone_group (id) ON DELETE CASCADE,
    origin_variant_fingerprint TEXT NOT NULL,
    language                  TEXT NOT NULL CHECK (language IN ('c', 'cpp')),
    file_path                 TEXT NOT NULL,
    start_line                INTEGER NOT NULL,
    end_line                  INTEGER NOT NULL,
    unit_name                 TEXT,
    token_count               INTEGER NOT NULL,
    PRIMARY KEY (group_id, origin_variant_fingerprint, file_path, start_line, end_line)
) STRICT;
CREATE TABLE cross_variant_comparison (
    id                    INTEGER PRIMARY KEY,
    comparison_id         BLOB NOT NULL CHECK (length(comparison_id) = 16),
    policy_version        TEXT NOT NULL,
    root_path             TEXT NOT NULL,
    started_at            TEXT NOT NULL,
    finished_at           TEXT NOT NULL
) STRICT;
CREATE TABLE cross_variant_comparison_origin (
    comparison_id              INTEGER NOT NULL REFERENCES cross_variant_comparison (id) ON DELETE CASCADE,
    build_variant_fingerprint  TEXT NOT NULL,
    PRIMARY KEY (comparison_id, build_variant_fingerprint)
) STRICT;
CREATE TABLE detector_version (
    id        INTEGER PRIMARY KEY,
    component TEXT NOT NULL,
    version   TEXT NOT NULL,
    UNIQUE (component, version)
) STRICT;
CREATE TABLE feature_fingerprint (
    id                     INTEGER PRIMARY KEY,
    kind                   TEXT NOT NULL CHECK (kind IN
                               ('statement_window', 'subtree', 'cfg',
                                'api_call_sequence', 'api_call_multiset')),
    hash_algo              TEXT NOT NULL,
    hash                   BLOB NOT NULL CHECK (length(hash) = 16),
    feature_schema_version TEXT NOT NULL,
    frontend_version       TEXT NOT NULL,
    analysis_mode          TEXT NOT NULL CHECK (analysis_mode IN ('fast', 'structural', 'semantic')),
    language               TEXT NOT NULL CHECK (language IN ('rust', 'c', 'cpp')),
    build_variant_id       INTEGER NOT NULL REFERENCES build_variant (id),
    UNIQUE (kind, hash_algo, hash, feature_schema_version, frontend_version,
            analysis_mode, language, build_variant_id)
) STRICT;
CREATE TABLE feature_occurrence (
    id                     INTEGER PRIMARY KEY,
    scan_run_id            INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    feature_fingerprint_id INTEGER NOT NULL REFERENCES feature_fingerprint (id),
    source_unit_id         INTEGER REFERENCES source_unit (id),
    start_byte             INTEGER NOT NULL,
    end_byte               INTEGER NOT NULL,
    extent                 INTEGER NOT NULL
) STRICT;
CREATE TABLE finding (
    id                                 INTEGER PRIMARY KEY,
    scan_run_id                        INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    clone_group_id                     INTEGER NOT NULL REFERENCES clone_group (id) ON DELETE CASCADE,
    suppression_id                     INTEGER REFERENCES suppression (id),
    clone_confidence                   REAL NOT NULL,
    semantic_confidence                REAL,
    source_artifact_mapping_confidence REAL,
    savings_confidence                 REAL,
    maintenance_risk                   REAL,
    refactoring_difficulty             REAL,
    final_priority                     REAL NOT NULL,
    observed_bytes                     INTEGER,
    duplicated_bytes                   INTEGER,
    retained_bytes                     INTEGER,
    shared_dependency_bytes            INTEGER,
    duplicated_data_bytes              INTEGER,
    upper_bound_savings_bytes          INTEGER,
    estimated_refactor_savings_bytes   INTEGER,
    verified_savings_bytes             INTEGER
) STRICT;
CREATE TABLE fingerprint (
    id                    INTEGER PRIMARY KEY,
    kind                  TEXT NOT NULL CHECK (kind IN ('unit', 'fragment', 'clone_group')),
    hash_algo             TEXT NOT NULL,
    hash                  BLOB NOT NULL CHECK (length(hash) = 16),
    normalization_version INTEGER NOT NULL,
    frontend_version      TEXT NOT NULL,
    analysis_mode         TEXT NOT NULL CHECK (analysis_mode IN ('fast', 'structural', 'semantic')),
    language              TEXT NOT NULL CHECK (language IN ('rust', 'c', 'cpp', '')),
    build_variant_id      INTEGER NOT NULL REFERENCES build_variant (id),
    UNIQUE (kind, hash_algo, hash, normalization_version, frontend_version,
            analysis_mode, language, build_variant_id),
    CHECK (kind = 'clone_group' OR (language <> '' AND frontend_version <> ''))
) STRICT;
CREATE TABLE fragment (
    id             INTEGER PRIMARY KEY,
    scan_run_id    INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    source_unit_id INTEGER REFERENCES source_unit (id),
    fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    fragment_kind  TEXT NOT NULL CHECK (fragment_kind IN
                       ('matched_run', 'function_body', 'loop_body', 'branch_body', 'statement_window')),
    file_path      TEXT NOT NULL,
    start_line     INTEGER,
    end_line       INTEGER,
    token_count    INTEGER NOT NULL
) STRICT;
CREATE TABLE run_funnel_drop (
    scan_run_id INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL,
    cause       TEXT NOT NULL,
    dropped     INTEGER NOT NULL,
    PRIMARY KEY (scan_run_id, position, ordinal)
) STRICT;
CREATE TABLE run_funnel_stage (
    scan_run_id INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    name        TEXT NOT NULL,
    passed      INTEGER NOT NULL,
    PRIMARY KEY (scan_run_id, position)
) STRICT;
CREATE TABLE run_summary (
    scan_run_id           INTEGER PRIMARY KEY REFERENCES scan_run (id) ON DELETE CASCADE,
    analyzed_total        INTEGER NOT NULL,
    analyzed_rust         INTEGER NOT NULL,
    analyzed_c            INTEGER NOT NULL,
    analyzed_cpp          INTEGER NOT NULL,
    lines                 INTEGER NOT NULL,
    tokens                INTEGER NOT NULL,
    lexer_diagnostics     INTEGER NOT NULL,
    unparsed_files        INTEGER,
    unparsed_tokens       INTEGER,
    excluded_generated    INTEGER NOT NULL,
    excluded_by_glob      INTEGER NOT NULL,
    excluded_too_large    INTEGER NOT NULL,
    excluded_binary       INTEGER NOT NULL,
    excluded_unreadable   INTEGER NOT NULL,
    excluded_symlinks     INTEGER NOT NULL,
    excluded_walk_errors  INTEGER NOT NULL,
    excluded_timed_out    INTEGER NOT NULL,
    excluded_skipped      INTEGER NOT NULL,
    guardrail_profile     TEXT,
    guardrail_max_file_bytes INTEGER,
    guardrail_parse_timeout_ms INTEGER,
    guardrail_helper_timeout_ms INTEGER,
    guardrail_posting_cap INTEGER,
    guardrail_pair_budget INTEGER,
    guardrail_max_component INTEGER,
    folded_runs           INTEGER NOT NULL,
    subsumed_runs         INTEGER NOT NULL,
    split_components      INTEGER NOT NULL,
    pair_budget_exhausted INTEGER NOT NULL CHECK (pair_budget_exhausted IN (0, 1)),
    baseline_digest       TEXT
) STRICT;
CREATE TABLE run_unused_suppression (
    scan_run_id INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,
    scope       TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    PRIMARY KEY (scan_run_id, ordinal)
) STRICT;
CREATE TABLE scan_run (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    build_variant_id INTEGER NOT NULL REFERENCES build_variant (id),
    root_path        TEXT NOT NULL,
    tool_version     TEXT NOT NULL,
    config_hash      TEXT NOT NULL,
    config_source    TEXT NOT NULL CHECK (config_source IN ('defaults', 'root', 'explicit')),
    config_path      TEXT,
    analysis_mode    TEXT NOT NULL CHECK (analysis_mode IN ('fast', 'structural', 'semantic')),
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    status           TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed')),
    min_clone_tokens INTEGER NOT NULL CHECK (min_clone_tokens > 0)
) STRICT;
CREATE TABLE scan_run_detector_version (
    scan_run_id         INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    detector_version_id INTEGER NOT NULL REFERENCES detector_version (id),
    PRIMARY KEY (scan_run_id, detector_version_id)
) STRICT;
CREATE TABLE scanned_file (
    scan_run_id   INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    language      TEXT NOT NULL CHECK (language IN ('rust', 'c', 'cpp')),
    byte_len      INTEGER NOT NULL,
    PRIMARY KEY (scan_run_id, relative_path)
) STRICT;
CREATE TABLE semantic_group_evidence (
    clone_group_id  INTEGER PRIMARY KEY REFERENCES clone_group (id) ON DELETE CASCADE,
    schema_version  TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    rule_version    INTEGER NOT NULL CHECK (rule_version > 0),
    rule_confidence REAL NOT NULL CHECK (rule_confidence >= 0 AND rule_confidence <= 1)
) STRICT;
CREATE TABLE semantic_node_mapping (
    clone_group_id INTEGER NOT NULL REFERENCES clone_group (id) ON DELETE CASCADE,
    corresponding_member INTEGER NOT NULL CHECK (corresponding_member > 0),
    canonical_node INTEGER NOT NULL CHECK (canonical_node >= 0),
    corresponding_node INTEGER NOT NULL CHECK (corresponding_node >= 0),
    PRIMARY KEY (clone_group_id, corresponding_member, canonical_node, corresponding_node)
) STRICT;
CREATE TABLE semantic_operation_graph (
    fragment_id     INTEGER PRIMARY KEY REFERENCES fragment (id) ON DELETE CASCADE,
    member_position INTEGER NOT NULL CHECK (member_position >= 0),
    schema_version  TEXT NOT NULL,
    graph_json      TEXT NOT NULL
) STRICT;
CREATE TABLE source_artifact_mapping (
    id                 INTEGER PRIMARY KEY,
    artifact_symbol_id INTEGER NOT NULL REFERENCES artifact_symbol (id) ON DELETE CASCADE,
    fragment_id        INTEGER REFERENCES fragment (id),
    source_unit_id     INTEGER REFERENCES source_unit (id),
    mapping_source     TEXT NOT NULL CHECK (mapping_source IN
                           ('dwarf', 'pdb', 'source_map', 'linker_map', 'fingerprint',
                            'call_graph', 'generic_origin', 'unmapped')),
    mapping_confidence REAL,
    unmapped           INTEGER NOT NULL CHECK (unmapped IN (0, 1)),
    CHECK (
        (unmapped = 1 AND fragment_id IS NULL AND source_unit_id IS NULL)
        OR (unmapped = 0 AND (fragment_id IS NOT NULL OR source_unit_id IS NOT NULL))
    )
) STRICT;
CREATE TABLE source_unit (
    id             INTEGER PRIMARY KEY,
    scan_run_id    INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    language       TEXT NOT NULL CHECK (language IN ('rust', 'c', 'cpp')),
    unit_kind      TEXT NOT NULL CHECK (unit_kind IN ('function', 'method', 'impl', 'record', 'closure')),
    name           TEXT,
    file_path      TEXT NOT NULL,
    start_line     INTEGER,
    end_line       INTEGER,
    token_count    INTEGER NOT NULL
) STRICT;
CREATE TABLE suppression (
    id      INTEGER PRIMARY KEY,
    scope   TEXT NOT NULL CHECK (scope IN
                ('path_glob', 'vendored_path', 'symbol_pattern', 'ast_pattern',
                 'inline_comment', 'attribute', 'stable_clone_id', 'baseline',
                 'generated_marker')),
    pattern TEXT NOT NULL,
    reason  TEXT,
    active  INTEGER NOT NULL CHECK (active IN (0, 1))
) STRICT;
CREATE TABLE unit_feature (
    source_unit_id         INTEGER PRIMARY KEY REFERENCES source_unit (id) ON DELETE CASCADE,
    feature_schema_version TEXT NOT NULL,
    vector_counts          BLOB NOT NULL,
    max_depth              INTEGER NOT NULL,
    node_count             INTEGER NOT NULL,
    cfg_op_count           INTEGER NOT NULL,
    cfg_max_loop_depth     INTEGER NOT NULL,
    cfg_branch_count       INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_scan_run_started ON scan_run (started_at DESC);
CREATE INDEX idx_fingerprint_kind_hash ON fingerprint (kind, hash);
CREATE INDEX idx_source_unit_run ON source_unit (scan_run_id);
CREATE INDEX idx_source_unit_fp ON source_unit (fingerprint_id);
CREATE INDEX idx_fragment_run ON fragment (scan_run_id);
CREATE INDEX idx_fragment_unit ON fragment (source_unit_id);
CREATE INDEX idx_fragment_fp ON fragment (fingerprint_id);
CREATE INDEX idx_member_finding ON clone_group_member (finding_id);
CREATE INDEX idx_finding_run_priority ON finding (scan_run_id, final_priority DESC);
CREATE INDEX idx_finding_group ON finding (clone_group_id);
CREATE INDEX idx_artifact_run ON artifact (scan_run_id);
CREATE INDEX idx_artifact_symbol_artifact ON artifact_symbol (artifact_id);
CREATE INDEX idx_artifact_symbol_code_hash ON artifact_symbol (code_hash);
CREATE INDEX idx_sam_symbol ON source_artifact_mapping (artifact_symbol_id);
CREATE INDEX idx_feature_fingerprint_kind_hash ON feature_fingerprint (kind, hash);
CREATE INDEX idx_feature_occurrence_run ON feature_occurrence (scan_run_id);
CREATE INDEX idx_feature_occurrence_fp ON feature_occurrence (feature_fingerprint_id);
CREATE INDEX idx_feature_occurrence_unit ON feature_occurrence (source_unit_id);
CREATE INDEX idx_clone_group_run ON clone_group (scan_run_id);
CREATE INDEX idx_clone_group_fp ON clone_group (group_fingerprint_id);
CREATE INDEX idx_compiler_unit_run ON compiler_unit (scan_run_id);
CREATE INDEX idx_compiler_unit_file ON compiler_unit (file_path);
CREATE INDEX idx_compiler_type_category ON compiler_type (category);
CREATE INDEX idx_compiler_symbol_id ON compiler_symbol (symbol_id);
CREATE INDEX idx_compiler_symbol_site ON compiler_symbol (expansion_file, expansion_start_byte);
CREATE INDEX idx_compiler_call_target ON compiler_call (target_symbol);
CREATE INDEX idx_compiler_call_api_name ON compiler_call (api_name);
CREATE INDEX idx_compiler_call_candidate_symbol ON compiler_call_candidate (symbol);
CREATE INDEX idx_compiler_instantiation_key ON compiler_instantiation (instantiation_key);
CREATE INDEX idx_build_variant_setting ON build_variant_setting (name, value);
CREATE INDEX idx_cross_variant_comparison_identity
    ON cross_variant_comparison (comparison_id, started_at DESC);
CREATE INDEX idx_cross_variant_clone_group_comparison
    ON cross_variant_clone_group (comparison_id);
CREATE INDEX idx_compiler_unexpanded_macro_site
    ON compiler_unexpanded_macro (invocation_file, invocation_start_byte);
CREATE INDEX idx_compiler_expression_site
    ON compiler_expression (expansion_file, expansion_start_byte);
CREATE INDEX idx_artifact_analysis_path_started
    ON artifact_analysis (path, started_at DESC);
CREATE INDEX idx_artifact_analysis_symbol_fingerprint
    ON artifact_analysis_symbol (fingerprint);
CREATE INDEX idx_artifact_analysis_build_variant
    ON artifact_analysis (build_variant_fingerprint);
CREATE INDEX idx_artifact_analysis_correlation_source_run
    ON artifact_analysis_correlation (source_scan_run_id);
CREATE INDEX idx_clone_group_member_fragment
    ON clone_group_member (fragment_id, clone_group_id);
CREATE INDEX idx_artifact_analysis_mapping_symbol
    ON artifact_analysis_source_mapping (artifact_analysis_id, artifact_symbol_fingerprint);
CREATE INDEX idx_artifact_analysis_mapping_source
    ON artifact_analysis_source_mapping
       (source_kind, source_fingerprint, source_instance_fingerprint);
CREATE INDEX idx_artifact_analysis_mapping_fragment_instance
    ON artifact_analysis_source_mapping
       (source_kind, source_instance_fingerprint, artifact_analysis_id);
CREATE INDEX idx_artifact_analysis_unmapped_source_reason
    ON artifact_analysis_unmapped_source (artifact_analysis_id, reason);
CREATE INDEX idx_artifact_analysis_savings_source_run
    ON artifact_analysis_clone_group_savings (source_scan_run_id, clone_group_fingerprint);
CREATE INDEX idx_artifact_savings_calibration_group
    ON artifact_analysis_savings_calibration (source_scan_run_id, clone_group_fingerprint);
CREATE INDEX idx_semantic_node_mapping_group ON semantic_node_mapping (clone_group_id);
CREATE INDEX idx_cross_language_comparison_identity
    ON cross_language_comparison (comparison_id, started_at DESC);
CREATE INDEX idx_cross_language_semantic_group_comparison
    ON cross_language_semantic_group (comparison_id);
"#;

/// Initialize a new database with the one supported pre-release layout.
pub(crate) fn initialize(conn: &mut Connection) -> Result<(), StoreError> {
    let has_meta: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta')",
        [],
        |row| row.get(0),
    )?;
    if !has_meta {
        let has_existing_tables: bool = conn.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_existing_tables {
            return Err(StoreError::UnsupportedSchema { found: 0 });
        }
        conn.execute_batch(
            "CREATE TABLE schema_meta (
                 id      INTEGER PRIMARY KEY CHECK (id = 1),
                 version INTEGER NOT NULL
             ) STRICT;",
        )?;
    }

    match version(conn)? {
        SCHEMA_VERSION => Ok(()),
        0 => apply_baseline(conn),
        found => Err(StoreError::UnsupportedSchema { found }),
    }
}

/// Apply the only baseline atomically and record which one it is.
fn apply_baseline(conn: &mut Connection) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    tx.execute_batch(BASELINE_SQL)?;
    tx.execute(
        "INSERT INTO schema_meta (id, version) VALUES (1, ?1)",
        [SCHEMA_VERSION],
    )?;
    tx.commit()?;
    Ok(())
}

/// The schema version currently recorded in `conn`.
pub(crate) fn version(conn: &Connection) -> Result<i64, StoreError> {
    Ok(conn.query_row(
        "SELECT COALESCE((SELECT version FROM schema_meta WHERE id = 1), 0)",
        [],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
