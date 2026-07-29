//! Schema definition and forward-only migration.
//!
//! The schema covers every audit entity: `ScanRun`, `BuildVariant`,
//! `SourceUnit`, `Fragment`, `Fingerprint`, `CloneGroup`, `GroupLineage`,
//! `Finding`, `Suppression`, `Artifact`, `ArtifactSymbol`,
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
//! - Savings and confidence live in separate columns; there is no single
//!   collapsed score column.
//!
//! Migrations are forward-only. `schema_meta` stores the version; opening a
//! database written by a newer tool fails with an explicit error instead of
//! guessing (downgrade is unsupported by design).

use rusqlite::Connection;

use crate::StoreError;

/// Current schema version. Bump together with an appended migration.
pub const SCHEMA_VERSION: i64 = 19;

/// Migration scripts, applied in order; index `i` migrates version `i` to
/// `i + 1`. Existing entries are frozen — schema changes append.
const MIGRATIONS: &[&str] = &[
    V1, V2, V3, V4, V5, V6, V7, V8, V9, V10, V11, V12, V13, V14, V15, V16, V17, V18, V19,
];

/// Version 1: the full entity set.
const V1: &str = "
CREATE TABLE detector_version (
    id        INTEGER PRIMARY KEY,
    component TEXT NOT NULL,
    version   TEXT NOT NULL,
    UNIQUE (component, version)
) STRICT;

CREATE TABLE build_variant (
    id                    INTEGER PRIMARY KEY,
    variant_fingerprint   TEXT NOT NULL UNIQUE,
    canonical             TEXT NOT NULL,
    analysis_mode         TEXT NOT NULL CHECK (analysis_mode IN ('fast', 'structural', 'semantic')),
    normalization_version INTEGER NOT NULL
) STRICT;

CREATE TABLE scan_run (
    id               INTEGER PRIMARY KEY,
    build_variant_id INTEGER NOT NULL REFERENCES build_variant (id),
    root_path        TEXT NOT NULL,
    tool_version     TEXT NOT NULL,
    config_hash      TEXT NOT NULL,
    analysis_mode    TEXT NOT NULL CHECK (analysis_mode IN ('fast', 'structural', 'semantic')),
    started_at       TEXT NOT NULL,
    finished_at      TEXT,
    status           TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed'))
) STRICT;
CREATE INDEX idx_scan_run_started ON scan_run (started_at DESC);

CREATE TABLE scan_run_detector_version (
    scan_run_id         INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    detector_version_id INTEGER NOT NULL REFERENCES detector_version (id),
    PRIMARY KEY (scan_run_id, detector_version_id)
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
CREATE INDEX idx_fingerprint_kind_hash ON fingerprint (kind, hash);

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
CREATE INDEX idx_source_unit_run ON source_unit (scan_run_id);
CREATE INDEX idx_source_unit_fp ON source_unit (fingerprint_id);

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
CREATE INDEX idx_fragment_run ON fragment (scan_run_id);
CREATE INDEX idx_fragment_unit ON fragment (source_unit_id);
CREATE INDEX idx_fragment_fp ON fragment (fingerprint_id);

CREATE TABLE clone_group (
    id                   INTEGER PRIMARY KEY,
    scan_run_id          INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    group_fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    clone_type           TEXT NOT NULL CHECK (clone_type IN ('type-1', 'type-2', 'type-3', 'restricted-semantic')),
    member_count         INTEGER NOT NULL,
    score                REAL NOT NULL,
    entropy_bits         REAL NOT NULL,
    suppress_reason      TEXT CHECK (suppress_reason IN ('low-entropy', 'high-frequency'))
) STRICT;
CREATE INDEX idx_clone_group_run ON clone_group (scan_run_id);
CREATE INDEX idx_clone_group_fp ON clone_group (group_fingerprint_id);

CREATE TABLE clone_group_member (
    clone_group_id INTEGER NOT NULL REFERENCES clone_group (id) ON DELETE CASCADE,
    fragment_id    INTEGER NOT NULL REFERENCES fragment (id) ON DELETE CASCADE,
    finding_id     BLOB NOT NULL CHECK (length(finding_id) = 16),
    is_canonical   INTEGER NOT NULL CHECK (is_canonical IN (0, 1)),
    PRIMARY KEY (clone_group_id, fragment_id)
) STRICT;
CREATE INDEX idx_member_finding ON clone_group_member (finding_id);

CREATE TABLE group_lineage (
    id                     INTEGER PRIMARY KEY,
    lineage_id             BLOB CHECK (lineage_id IS NULL OR length(lineage_id) = 16),
    group_fingerprint_id   INTEGER NOT NULL REFERENCES fingerprint (id),
    previous_lineage_id    INTEGER REFERENCES group_lineage (id),
    first_seen_scan_run_id INTEGER REFERENCES scan_run (id),
    last_seen_scan_run_id  INTEGER REFERENCES scan_run (id)
) STRICT;

CREATE TABLE suppression (
    id      INTEGER PRIMARY KEY,
    scope   TEXT NOT NULL CHECK (scope IN
                ('path_glob', 'symbol_pattern', 'ast_pattern', 'inline_comment',
                 'attribute', 'stable_clone_id', 'baseline', 'generated_marker')),
    pattern TEXT NOT NULL,
    reason  TEXT,
    active  INTEGER NOT NULL CHECK (active IN (0, 1))
) STRICT;

CREATE TABLE finding (
    id                                 INTEGER PRIMARY KEY,
    scan_run_id                        INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    clone_group_id                     INTEGER NOT NULL REFERENCES clone_group (id) ON DELETE CASCADE,
    audit_state                        TEXT NOT NULL CHECK (audit_state IN
                                           ('new', 'unchanged', 'resolved', 'expanded',
                                            'reduced', 'moved', 'diverged', 'reclassified')),
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
CREATE INDEX idx_finding_run_priority ON finding (scan_run_id, final_priority DESC);
CREATE INDEX idx_finding_group ON finding (clone_group_id);

CREATE TABLE artifact (
    id                 INTEGER PRIMARY KEY,
    scan_run_id        INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    build_variant_id   INTEGER NOT NULL REFERENCES build_variant (id),
    format             TEXT NOT NULL CHECK (format IN ('wasm', 'elf', 'macho', 'pecoff', 'object', 'archive')),
    path               TEXT NOT NULL,
    total_size_bytes   INTEGER NOT NULL,
    code_section_bytes INTEGER,
    data_section_bytes INTEGER,
    content_hash       TEXT NOT NULL
) STRICT;
CREATE INDEX idx_artifact_run ON artifact (scan_run_id);

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
CREATE INDEX idx_artifact_symbol_artifact ON artifact_symbol (artifact_id);
CREATE INDEX idx_artifact_symbol_code_hash ON artifact_symbol (code_hash);

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
CREATE INDEX idx_sam_symbol ON source_artifact_mapping (artifact_symbol_id);
";

/// Version 2: candidate-extraction feature storage for Structural mode.
///
/// These tables hold feature hashes, which are candidate-index keys, not
/// stable identifiers — kept separate from `fingerprint` (whose rows are
/// stable ids) on purpose. A feature hash is valid only within one
/// `feature_schema_version`, which is part of the dedup key.
const V2: &str = "
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
CREATE INDEX idx_feature_fingerprint_kind_hash ON feature_fingerprint (kind, hash);

CREATE TABLE feature_occurrence (
    id                     INTEGER PRIMARY KEY,
    scan_run_id            INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    feature_fingerprint_id INTEGER NOT NULL REFERENCES feature_fingerprint (id),
    source_unit_id         INTEGER REFERENCES source_unit (id),
    start_byte             INTEGER NOT NULL,
    end_byte               INTEGER NOT NULL,
    extent                 INTEGER NOT NULL
) STRICT;
CREATE INDEX idx_feature_occurrence_run ON feature_occurrence (scan_run_id);
CREATE INDEX idx_feature_occurrence_fp ON feature_occurrence (feature_fingerprint_id);
CREATE INDEX idx_feature_occurrence_unit ON feature_occurrence (source_unit_id);

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
";

/// Version 3: the per-group similarity breakdown for Structural findings.
///
/// A group's similarity is never a single collapsed number; the breakdown
/// keeps each measured dimension visible. `type_similarity` is nullable because
/// Structural mode resolves no types, and the breakdown carries the weight
/// recipe version it was scored under so a later reweighting is a versioned
/// event. One row per group; Fast-mode groups write none.
const V3: &str = "
CREATE TABLE clone_group_similarity (
    clone_group_id  INTEGER PRIMARY KEY REFERENCES clone_group (id) ON DELETE CASCADE,
    weight_version  TEXT NOT NULL,
    lexical         REAL NOT NULL,
    structural      REAL NOT NULL,
    control_flow    REAL NOT NULL,
    type_similarity REAL,
    api             REAL NOT NULL,
    composite       REAL NOT NULL,
    min_pairwise    REAL NOT NULL
) STRICT;
";

/// Version 4: the boilerplate shape a clone group matches.
///
/// This records what the group *is*, not what was done about it: whether a
/// category is hidden, ranked down or shown is a configured policy, and the
/// stored fact stays the same under every policy. A group whose members do not
/// all match the same shape stores nothing.
const V4: &str = "
ALTER TABLE clone_group ADD COLUMN boilerplate TEXT
    CHECK (boilerplate IN ('trivial-body', 'forwarding', 'macro-repetition'));
";

/// Version 5: the confidence band a group's verdict was assigned.
///
/// The band is not derivable from the stored numbers — it is the weakest band
/// across the group's internal edges, lowered when no type evidence was
/// available — so reporting it from the database requires storing it. Nullable
/// because rows written before this column carry no band, and a band is a
/// judgement that must not be invented after the fact.
const V5: &str = "
ALTER TABLE clone_group_similarity ADD COLUMN confidence_band TEXT
    CHECK (confidence_band IN ('high', 'medium', 'low'));
";

/// Version 6: the api dimension becomes nullable.
///
/// Two units that call nothing have no call surfaces to compare, and the
/// dimension is then absent rather than in perfect agreement — the same
/// distinction `type_similarity` already carries. `SQLite` cannot drop a NOT
/// NULL constraint in place, so the table is rebuilt; every existing row was
/// written with a value and keeps it.
const V6: &str = "
CREATE TABLE clone_group_similarity_new (
    clone_group_id  INTEGER PRIMARY KEY REFERENCES clone_group (id) ON DELETE CASCADE,
    weight_version  TEXT NOT NULL,
    lexical         REAL NOT NULL,
    structural      REAL NOT NULL,
    control_flow    REAL NOT NULL,
    type_similarity REAL,
    api             REAL,
    composite       REAL NOT NULL,
    min_pairwise    REAL NOT NULL,
    confidence_band TEXT CHECK (confidence_band IN ('high', 'medium', 'low'))
) STRICT;
INSERT INTO clone_group_similarity_new
    SELECT clone_group_id, weight_version, lexical, structural, control_flow,
           type_similarity, api, composite, min_pairwise, confidence_band
    FROM clone_group_similarity;
DROP TABLE clone_group_similarity;
ALTER TABLE clone_group_similarity_new RENAME TO clone_group_similarity;
";

/// Version 7: what a clone group's members are.
///
/// A group whose members are runs of statements inside otherwise-unrelated
/// units says something different about the code from one whose members are
/// whole duplicated units. The difference could be guessed by comparing each
/// member's line anchors against its host unit's, but that is inference from
/// position, and it gives the wrong answer for a run that happens to span its
/// whole host. The fact is recorded instead. Every row written before this
/// column described a whole unit, which is what the default records.
const V7: &str = "
ALTER TABLE clone_group ADD COLUMN member_scope TEXT NOT NULL DEFAULT 'unit'
    CHECK (member_scope IN ('unit', 'fragment'));
";

/// Version 8: whether a clone group lives entirely in a test suite.
///
/// A suite repeats itself deliberately, so duplication inside one says
/// something different from duplication in the code it exercises, and a report
/// that cannot tell them apart is dominated by the suite. Recording it makes
/// the distinction available to history as well as to the report that found
/// it. Rows written before this column predate the recognition rules and are
/// not claimed to be test code, which is what the default records.
const V8: &str = "
ALTER TABLE clone_group ADD COLUMN test_code INTEGER NOT NULL DEFAULT 0
    CHECK (test_code IN (0, 1));
";

/// Version 9: whether a clone group is a pair no larger group could hold.
///
/// A group asserts that every member is a copy of every other, and being a
/// copy is not transitive, so a unit can be a copy of two units that are not
/// copies of each other. Only one of those relations fits in a partition; the
/// other is reported as its own two-member group, and it is the one kind of
/// group whose members also appear in another. History has to be able to tell
/// the two apart — a pair appearing beside the group that excluded it is not
/// the same event as a group gaining a member. Rows written before this column
/// were all partition members, which is what the default records.
const V9: &str = "
ALTER TABLE clone_group ADD COLUMN split_pair INTEGER NOT NULL DEFAULT 0
    CHECK (split_pair IN (0, 1));
";

/// Version 10: a fourth boilerplate shape.
///
/// The vocabulary is a `CHECK` rather than a lookup table, so widening it means
/// rebuilding the table `SQLite` will not alter in place. Every existing value
/// stays valid — the list only grows — so the rows carry over unchanged.
const V10: &str = "
CREATE TABLE clone_group_new (
    id                   INTEGER PRIMARY KEY,
    scan_run_id          INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    group_fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    clone_type           TEXT NOT NULL CHECK (clone_type IN ('type-1', 'type-2', 'type-3', 'restricted-semantic')),
    member_count         INTEGER NOT NULL,
    score                REAL NOT NULL,
    entropy_bits         REAL NOT NULL,
    suppress_reason      TEXT CHECK (suppress_reason IN ('low-entropy', 'high-frequency')),
    boilerplate          TEXT CHECK (boilerplate IN ('trivial-body', 'forwarding', 'macro-repetition', 'guarded-dispatch')),
    member_scope         TEXT NOT NULL DEFAULT 'unit' CHECK (member_scope IN ('unit', 'fragment')),
    test_code            INTEGER NOT NULL DEFAULT 0 CHECK (test_code IN (0, 1)),
    split_pair           INTEGER NOT NULL DEFAULT 0 CHECK (split_pair IN (0, 1))
) STRICT;
INSERT INTO clone_group_new
    SELECT id, scan_run_id, group_fingerprint_id, clone_type, member_count,
           score, entropy_bits, suppress_reason, boilerplate, member_scope,
           test_code, split_pair
    FROM clone_group;
DROP TABLE clone_group;
ALTER TABLE clone_group_new RENAME TO clone_group;
CREATE INDEX idx_clone_group_run ON clone_group (scan_run_id);
CREATE INDEX idx_clone_group_fp ON clone_group (group_fingerprint_id);
";

/// Version 11: the files a run read, with the hash of what it read.
///
/// A run's findings say what was found, not what was looked at, and the
/// difference is what a later run needs: a file that vanished between two
/// scans leaves no trace in either set of findings. One row per discovered
/// file makes the tree a run saw recoverable, so the next scan of it can say
/// what moved and, later, reuse what did not.
///
/// The hash is of bytes and nothing else — no timestamp, no size shortcut — so
/// the comparison never depends on a filesystem's bookkeeping.
const V11: &str = "
CREATE TABLE scanned_file (
    scan_run_id   INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    content_hash  TEXT NOT NULL,
    language      TEXT NOT NULL CHECK (language IN ('rust', 'c', 'cpp')),
    byte_len      INTEGER NOT NULL,
    PRIMARY KEY (scan_run_id, relative_path)
) STRICT;
";

/// Version 12: which history each group belongs to, and what connects it
/// there.
///
/// The V1 shape carried one `previous_lineage_id` per row, which can express a
/// group that continued and a group that split, but not two groups that merged
/// into one — a case the comparison genuinely produces. Connections move into
/// their own table, where a child can have several parents and the run that
/// observed each connection is on the row: a lineage edge is something one
/// audit concluded, not a timeless fact about the code.
///
/// `last_seen_scan_run_id` and `first_seen_scan_run_id` go with it. Both are
/// the extremes of the rows already present for a lineage, and a stored copy
/// of a derivable value is a second answer waiting to disagree with the first.
///
/// The table is replaced rather than rebuilt through a copy. No release
/// between V1 and V11 wrote a row into it — the schema was the contract and
/// the population came later — so there is nothing to carry over, and a copy
/// statement would only bind this migration to column names that a database
/// restored from an older shape need not still have.
const V12: &str = "
DROP TABLE IF EXISTS group_lineage;
CREATE TABLE group_lineage (
    scan_run_id          INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    lineage_id           BLOB NOT NULL CHECK (length(lineage_id) = 16),
    group_fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    PRIMARY KEY (scan_run_id, group_fingerprint_id)
) STRICT;
CREATE INDEX idx_group_lineage_id ON group_lineage (lineage_id);

CREATE TABLE group_lineage_edge (
    scan_run_id                 INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    child_group_fingerprint_id  INTEGER NOT NULL REFERENCES fingerprint (id),
    parent_group_fingerprint_id INTEGER NOT NULL REFERENCES fingerprint (id),
    parent_lineage_id           BLOB NOT NULL CHECK (length(parent_lineage_id) = 16),
    is_primary                  INTEGER NOT NULL CHECK (is_primary IN (0, 1)),
    shared_content              INTEGER NOT NULL,
    overlap                     REAL NOT NULL,
    PRIMARY KEY (scan_run_id, child_group_fingerprint_id, parent_group_fingerprint_id)
) STRICT;
CREATE INDEX idx_group_lineage_edge_parent ON group_lineage_edge (parent_group_fingerprint_id);
";

/// Version 13: the length floor a run reported under.
///
/// The floor decides which matches become findings at all, and the ranking
/// reads every group's size against it: a clone sitting on the floor is the
/// weakest evidence the run could produce, and one at eight times the floor is
/// not, whatever the floor was set to. Without it stored, a finding's ranking
/// can be shown but not re-derived, and two runs of the same tree under
/// different floors look like one run that changed its mind.
///
/// Rows written before this migration have no floor to record. It is nullable
/// for that reason, and read back as absent rather than as the current
/// default, which would attribute a setting to a run that never used it.
const V13: &str = "
ALTER TABLE scan_run ADD COLUMN min_clone_tokens INTEGER;
";

/// Version 14: whether a group's members differ by one integer width and
/// nothing else.
///
/// Stored beside `boilerplate` and for the same reason: what a group is and
/// what a report does with it are separate decisions, and only the first
/// belongs in an audit record. A column rather than a `boilerplate` value —
/// that vocabulary classifies one body, and this is a statement about how two
/// bodies differ, which no member carries alone.
///
/// Rows written before this migration were never asked, and `0` is what a group
/// that was asked and said no records. The difference does not matter to any
/// reader: the answer is recomputed on every scan, and no query treats the
/// column as history.
const V14: &str = "
ALTER TABLE clone_group ADD COLUMN width_family INTEGER NOT NULL DEFAULT 0
    CHECK (width_family IN (0, 1));
";

/// Version 15: a fifth boilerplate shape.
///
/// Widening the `CHECK` means rebuilding the table again, the way V10 did.
/// Every existing value stays valid — the list only grows — so the rows carry
/// over unchanged, and the columns added since V10 come across with them.
const V15: &str = "
CREATE TABLE clone_group_new (
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
    split_pair           INTEGER NOT NULL DEFAULT 0 CHECK (split_pair IN (0, 1)),
    width_family         INTEGER NOT NULL DEFAULT 0 CHECK (width_family IN (0, 1))
) STRICT;
INSERT INTO clone_group_new
    SELECT id, scan_run_id, group_fingerprint_id, clone_type, member_count,
           score, entropy_bits, suppress_reason, boilerplate, member_scope,
           test_code, split_pair, width_family
    FROM clone_group;
DROP TABLE clone_group;
ALTER TABLE clone_group_new RENAME TO clone_group;
CREATE INDEX idx_clone_group_run ON clone_group (scan_run_id);
CREATE INDEX idx_clone_group_fp ON clone_group (group_fingerprint_id);
";

/// Version 16: what a run reported beyond its findings.
///
/// A run's rows say what was found and what was read; a report also says how
/// much source that was, what the pipeline dropped on the way, and which
/// configured rule hid nothing. None of it is derivable from the findings —
/// a stage that discarded everything leaves no row anywhere — so a stored run
/// could be listed again but not described again.
///
/// The funnel is two tables rather than one with a nullable cause: a stage
/// and a reason for leaving it are different things, and a stage that dropped
/// nothing has no drop row rather than a row saying nothing was dropped.
///
/// `baseline_digest` names the frozen set a run was reported against. Two runs
/// of one tree under one configuration still differ when different findings
/// were frozen, and the baseline file is not part of the configuration hash.
const V16: &str = "
ALTER TABLE clone_group ADD COLUMN statements INTEGER;

CREATE TABLE run_summary (
    scan_run_id           INTEGER PRIMARY KEY REFERENCES scan_run (id) ON DELETE CASCADE,
    lines                 INTEGER NOT NULL,
    tokens                INTEGER NOT NULL,
    lexer_diagnostics     INTEGER NOT NULL,
    unparsed_files        INTEGER,
    unparsed_tokens       INTEGER,
    excluded_generated    INTEGER NOT NULL,
    excluded_by_glob      INTEGER NOT NULL,
    excluded_skipped      INTEGER NOT NULL,
    folded_runs           INTEGER NOT NULL,
    subsumed_runs         INTEGER NOT NULL,
    split_components      INTEGER NOT NULL,
    pair_budget_exhausted INTEGER NOT NULL CHECK (pair_budget_exhausted IN (0, 1)),
    baseline_digest       TEXT
) STRICT;

CREATE TABLE run_funnel_stage (
    scan_run_id INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    name        TEXT NOT NULL,
    passed      INTEGER NOT NULL,
    PRIMARY KEY (scan_run_id, position)
) STRICT;

CREATE TABLE run_funnel_drop (
    scan_run_id INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    position    INTEGER NOT NULL,
    ordinal     INTEGER NOT NULL,
    cause       TEXT NOT NULL,
    dropped     INTEGER NOT NULL,
    PRIMARY KEY (scan_run_id, position, ordinal)
) STRICT;

CREATE TABLE run_unused_suppression (
    scan_run_id INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    ordinal     INTEGER NOT NULL,
    scope       TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    PRIMARY KEY (scan_run_id, ordinal)
) STRICT;
";

/// Version 17: what a compiler was asked about, and what it answered.
///
/// A `compiler_unit` row exists for every unit a run put to a helper,
/// including the ones nothing could answer for. A unit nobody could analyse is
/// an ordinary outcome of scanning a real project — a crate whose build script
/// would have to run, a file no compile command mentions — and recording it as
/// an absence of rows would make it indistinguishable from a unit nobody
/// asked about. `unavailable_reason` says which, and the row carries no
/// payload; a row with a `schema_version` carries one and no reason.
///
/// The same distinction repeats inside an answer. An empty control-flow graph
/// and a helper that builds none produce the same zero block rows, as do an
/// effect summary that found nothing and one nobody computed, so `has_cfg`,
/// `effects_computed` and `data_flow_computed` are stored: the emptiness is
/// visible either way, and only these say whether anyone looked.
/// `compiler_call_candidate` is there for the same reason — a dynamic call
/// whose candidate set is empty is a different fact from an unresolved one,
/// and both would otherwise be a call with no candidate rows.
///
/// Nothing here has a foreign key into `source_unit`. A compiler unit is a
/// translation unit or a crate and a source unit is a function; one covers many
/// of the other, and the relation between a resolved symbol and the unit it
/// sits inside is containment of one anchor in another. Materialising it as a
/// key would assert a correspondence that does not exist, and computing it
/// from line anchors at write time would store an inference beside the fact it
/// was inferred from. The anchor columns are indexed instead, so the join is
/// available to whoever wants it and is not asserted by whoever does not.
///
/// `instantiation_key` is indexed without the unit in front of it, because the
/// family it names is exactly the thing that spans units: one generic
/// definition and every place it was instantiated. That is the query the
/// expansion/definition anchoring exists to serve — one definition with twenty
/// expansions rather than twenty clones — and scoping the index to a unit would
/// answer it only within a file.
const V17: &str = "
CREATE TABLE compiler_helper (
    id              INTEGER PRIMARY KEY,
    scan_run_id     INTEGER NOT NULL REFERENCES scan_run (id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    protocol_min    INTEGER NOT NULL,
    protocol_max    INTEGER NOT NULL,
    protocol_agreed INTEGER NOT NULL,
    UNIQUE (scan_run_id, name, version)
) STRICT;

CREATE TABLE compiler_helper_capability (
    compiler_helper_id INTEGER NOT NULL REFERENCES compiler_helper (id) ON DELETE CASCADE,
    capability         TEXT NOT NULL,
    PRIMARY KEY (compiler_helper_id, capability)
) STRICT;

CREATE TABLE compiler_helper_toolchain (
    compiler_helper_id INTEGER NOT NULL REFERENCES compiler_helper (id) ON DELETE CASCADE,
    toolchain          TEXT NOT NULL,
    PRIMARY KEY (compiler_helper_id, toolchain)
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
    data_flow_computed INTEGER NOT NULL CHECK (data_flow_computed IN (0, 1)),
    UNIQUE (scan_run_id, unit_name, file_path, variant_key),
    CHECK ((schema_version IS NULL) <> (unavailable_reason IS NULL)),
    CHECK (unavailable_reason IS NULL
           OR (has_cfg = 0 AND effects_computed = 0 AND data_flow_computed = 0))
) STRICT;
CREATE INDEX idx_compiler_unit_run ON compiler_unit (scan_run_id);
CREATE INDEX idx_compiler_unit_file ON compiler_unit (file_path);

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
CREATE INDEX idx_compiler_type_category ON compiler_type (category);

CREATE TABLE compiler_type_argument (
    compiler_unit_id INTEGER NOT NULL,
    type_index       INTEGER NOT NULL,
    position         INTEGER NOT NULL,
    argument_index   INTEGER NOT NULL,
    PRIMARY KEY (compiler_unit_id, type_index, position),
    FOREIGN KEY (compiler_unit_id, type_index)
        REFERENCES compiler_type (compiler_unit_id, type_index) ON DELETE CASCADE
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
CREATE INDEX idx_compiler_symbol_id ON compiler_symbol (symbol_id);
CREATE INDEX idx_compiler_symbol_site ON compiler_symbol (expansion_file, expansion_start_byte);

CREATE TABLE compiler_call (
    id                    INTEGER PRIMARY KEY,
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    resolution            TEXT NOT NULL CHECK (resolution IN
                              ('static', 'dynamic', 'unresolved')),
    target_symbol         TEXT,
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
CREATE INDEX idx_compiler_call_target ON compiler_call (target_symbol);

CREATE TABLE compiler_call_candidate (
    compiler_call_id INTEGER NOT NULL REFERENCES compiler_call (id) ON DELETE CASCADE,
    position         INTEGER NOT NULL,
    symbol           TEXT NOT NULL,
    PRIMARY KEY (compiler_call_id, position)
) STRICT;
CREATE INDEX idx_compiler_call_candidate_symbol ON compiler_call_candidate (symbol);

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

CREATE TABLE compiler_edge (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal          INTEGER NOT NULL,
    from_block       INTEGER NOT NULL,
    to_block         INTEGER NOT NULL,
    edge_kind        TEXT NOT NULL CHECK (edge_kind IN
                         ('flow', 'taken', 'not_taken', 'unwind', 'return')),
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;

CREATE TABLE compiler_instantiation (
    id                    INTEGER PRIMARY KEY,
    compiler_unit_id      INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal               INTEGER NOT NULL,
    definition            TEXT NOT NULL,
    instantiation_key     TEXT NOT NULL,
    expansion_file        TEXT NOT NULL,
    expansion_start_byte  INTEGER NOT NULL,
    expansion_end_byte    INTEGER NOT NULL,
    expansion_start_line  INTEGER NOT NULL,
    definition_file       TEXT,
    definition_start_byte INTEGER,
    definition_end_byte   INTEGER,
    definition_start_line INTEGER,
    UNIQUE (compiler_unit_id, ordinal)
) STRICT;
CREATE INDEX idx_compiler_instantiation_key ON compiler_instantiation (instantiation_key);

CREATE TABLE compiler_instantiation_argument (
    compiler_instantiation_id INTEGER NOT NULL
                                  REFERENCES compiler_instantiation (id) ON DELETE CASCADE,
    position                  INTEGER NOT NULL,
    type_index                INTEGER NOT NULL,
    PRIMARY KEY (compiler_instantiation_id, position)
) STRICT;

CREATE TABLE compiler_effect (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal          INTEGER NOT NULL,
    effect_kind      TEXT NOT NULL CHECK (effect_kind IN ('write', 'interaction')),
    subject          TEXT NOT NULL,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;

CREATE TABLE compiler_data_flow (
    compiler_unit_id INTEGER NOT NULL REFERENCES compiler_unit (id) ON DELETE CASCADE,
    ordinal          INTEGER NOT NULL,
    source_symbol    TEXT NOT NULL,
    sink_symbol      TEXT NOT NULL,
    PRIMARY KEY (compiler_unit_id, ordinal)
) STRICT;
";

/// Version 18: what a variant was, beside the hash it is known by.
///
/// A variant row held its canonical form, and a canonical form names a
/// resolved build configuration by fingerprint rather than by content. Two
/// stored runs could therefore be shown to be incomparable without anything
/// being able to say what differed — a define, a feature, a target — which is
/// the one question a reader has at that point.
///
/// The settings go in a child table rather than in columns: they are lists
/// whose order is meaning (an include path is a search order), the two
/// languages name different things, and joining them into one column would
/// re-introduce the delimiter ambiguity the canonical encoding exists to avoid.
/// The enabled languages *are* joined into one column, because their names are
/// a closed set of words with no punctuation in them.
///
/// The new columns are nullable and nothing is backfilled. A row written
/// before this version was not described, and an empty description is a
/// different claim — that a build was resolved and said nothing — so the two
/// are kept apart. A later run under the same variant fills the row in.
const V18: &str = "
ALTER TABLE build_variant ADD COLUMN languages TEXT;
ALTER TABLE build_variant ADD COLUMN header_language TEXT
    CHECK (header_language IS NULL OR header_language IN ('rust', 'c', 'cpp', ''));
ALTER TABLE build_variant ADD COLUMN build_language TEXT
    CHECK (build_language IS NULL OR build_language IN ('rust', 'cpp', ''));

CREATE TABLE build_variant_setting (
    build_variant_id INTEGER NOT NULL REFERENCES build_variant (id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    position         INTEGER NOT NULL,
    value            TEXT NOT NULL,
    PRIMARY KEY (build_variant_id, name, position)
) STRICT;
CREATE INDEX idx_build_variant_setting ON build_variant_setting (name, value);
";

/// Version 19: how much trouble a helper was, beside what it is.
///
/// A helper that had to be restarted analysed the tree in pieces, and every
/// restart is a unit that cost two attempts. The unit rows say which files came
/// back empty but not that the emptiness came from the helper falling over, so
/// a stored run could report a thin result with no sign of why it was thin.
///
/// Nullable and not backfilled: zero would be a claim that the run went
/// smoothly, and a run recorded before this version says nothing either way.
const V19: &str = "
ALTER TABLE compiler_helper ADD COLUMN restarts INTEGER
    CHECK (restarts IS NULL OR restarts >= 0);
";

/// Bring `conn` to the current schema version, applying any pending
/// forward migrations inside one transaction per step.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (
             id      INTEGER PRIMARY KEY CHECK (id = 1),
             version INTEGER NOT NULL
         ) STRICT;",
    )?;
    let found: i64 = conn.query_row(
        "SELECT COALESCE((SELECT version FROM schema_meta WHERE id = 1), 0)",
        [],
        |row| row.get(0),
    )?;
    if found > SCHEMA_VERSION {
        return Err(StoreError::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    let start = usize::try_from(found).unwrap_or(usize::MAX);
    if start >= MIGRATIONS.len() {
        return Ok(());
    }
    // A migration that widens a `CHECK` has to rebuild its table, and with
    // foreign keys enforced `DROP TABLE` runs an implicit `DELETE FROM` that
    // fires every `ON DELETE CASCADE` hanging off it. The table comes back
    // with its rows and the children are gone. Enforcement is therefore off
    // for the duration and the result is checked instead: the scripts move
    // rows across by primary key, so nothing they do can orphan a reference
    // that was whole beforehand, and `foreign_key_check` says so rather than
    // being taken on trust. It cannot be a transaction-scoped setting —
    // `foreign_keys` is a no-op inside one.
    let enforced = conn.pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))?;
    conn.pragma_update(None, "foreign_keys", false)?;
    let outcome = apply(conn, start);
    let checked = outcome.and_then(|()| orphans(conn));
    conn.pragma_update(None, "foreign_keys", enforced != 0)?;
    checked
}

/// Run every migration from `start` onwards, one transaction per step.
fn apply(conn: &mut Connection, start: usize) -> Result<(), StoreError> {
    for step in start..MIGRATIONS.len() {
        apply_one(conn, step)?;
    }
    Ok(())
}

/// Migrate version `step` to `step + 1` in one transaction, recording the new
/// version with the change it describes.
fn apply_one(conn: &mut Connection, step: usize) -> Result<(), StoreError> {
    let tx = conn.transaction()?;
    tx.execute_batch(MIGRATIONS[step])?;
    let next = i64::try_from(step + 1).unwrap_or(i64::MAX);
    tx.execute(
        "INSERT INTO schema_meta (id, version) VALUES (1, ?1)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version",
        [next],
    )?;
    tx.commit()?;
    Ok(())
}

/// Fail when migrating left a reference pointing at a row that is not there.
fn orphans(conn: &Connection) -> Result<(), StoreError> {
    let broken: i64 =
        conn.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if broken > 0 {
        return Err(StoreError::MigrationOrphanedRows { rows: broken });
    }
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
mod tests {
    use super::*;

    /// One group with one member, and the chain of rows they need to exist.
    ///
    /// Every insert names its columns. Positional inserts would tie the seed to
    /// how wide each table happened to be when it was written, so a migration
    /// that adds a column would break the tests about migrating rather than be
    /// tested by them.
    const SEED: &str = "
INSERT INTO build_variant (id, variant_fingerprint, canonical, analysis_mode,
                           normalization_version)
    VALUES (1, 'v', 'canonical', 'structural', 1);
INSERT INTO scan_run (id, build_variant_id, root_path, tool_version, config_hash,
                      analysis_mode, started_at, status)
    VALUES (1, 1, '/tree', '0.1.0', 'cfg', 'structural', '2026-01-01T00:00:00Z', 'completed');
INSERT INTO fingerprint (id, kind, hash_algo, hash, normalization_version,
                         frontend_version, analysis_mode, language, build_variant_id)
    VALUES (1, 'clone_group', 'blake3', randomblob(16), 1, '', 'structural', '', 1),
           (2, 'fragment', 'blake3', randomblob(16), 1, 'f1', 'structural', 'rust', 1);
INSERT INTO fragment (id, scan_run_id, fingerprint_id, fragment_kind, file_path,
                      start_line, end_line, token_count)
    VALUES (1, 1, 2, 'function_body', 'src/lib.rs', 1, 9, 40);
INSERT INTO clone_group (id, scan_run_id, group_fingerprint_id, clone_type,
                         member_count, score, entropy_bits)
    VALUES (1, 1, 1, 'type-2', 1, 0.5, 8.0);
INSERT INTO clone_group_member (clone_group_id, fragment_id, finding_id, is_canonical)
    VALUES (1, 1, randomblob(16), 1);
";

    /// A database genuinely at `version`, seeded with a group and its one
    /// member.
    ///
    /// The migrations up to `version` are the ones that run: winding the
    /// recorded version back after applying all of them would leave a database
    /// that has already seen the step under test, and a step that cannot be
    /// applied twice — adding a column, say — would fail for that reason
    /// rather than for the reason the test is about.
    fn seeded(version: i64) -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY CHECK (id = 1),
                                       version INTEGER NOT NULL) STRICT;",
        )
        .unwrap();
        let stop = usize::try_from(version).unwrap();
        for step in 0..stop {
            apply_one(&mut conn, step).unwrap();
        }
        conn.execute_batch(SEED).unwrap();
        conn
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    /// Rebuilding a table under enforced foreign keys deletes everything that
    /// cascades off it: `DROP TABLE` runs an implicit `DELETE FROM` first. The
    /// group survives either way — it is the member that says whether the
    /// rebuild took the rest of the audit with it.
    #[test]
    fn rebuilding_a_table_keeps_what_hangs_off_it() {
        // One version short of current, so the newest migration runs here
        // whatever it turns out to be, and a later rebuild is covered too.
        let mut conn = seeded(i64::try_from(MIGRATIONS.len()).unwrap() - 1);
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(count(&conn, "clone_group"), 1);
        assert_eq!(count(&conn, "clone_group_member"), 1);
    }

    /// Enforcement is off while migrating, so it has to be back on afterwards.
    #[test]
    fn migrating_leaves_foreign_keys_as_it_found_them() {
        let mut conn = seeded(i64::try_from(MIGRATIONS.len()).unwrap() - 1);
        conn.pragma_update(None, "foreign_keys", true).unwrap();
        migrate(&mut conn).unwrap();
        let enforced: i64 = conn
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .unwrap();
        assert_eq!(enforced, 1);
    }

    /// A reference left pointing nowhere is reported rather than carried
    /// forward: with enforcement off, nothing else would notice.
    #[test]
    fn a_reference_left_pointing_nowhere_fails_the_migration() {
        let mut conn = seeded(i64::try_from(MIGRATIONS.len()).unwrap() - 1);
        // Off first, so the delete leaves the member pointing nowhere
        // instead of taking it along: a database can arrive in this state,
        // and migrating it must say so.
        conn.pragma_update(None, "foreign_keys", false).unwrap();
        conn.execute("DELETE FROM fragment", []).unwrap();
        let error = migrate(&mut conn).unwrap_err();
        assert!(
            matches!(error, StoreError::MigrationOrphanedRows { rows } if rows == 1),
            "unexpected error: {error}"
        );
    }
}
