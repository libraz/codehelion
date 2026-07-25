//! Schema definition and forward-only migration.
//!
//! The schema covers every audit entity: `ScanRun`, `BuildVariant`,
//! `SourceUnit`, `Fragment`, `Fingerprint`, `CloneGroup`, `GroupLineage`,
//! `Finding`, `Suppression`, `Artifact`, `ArtifactSymbol`,
//! `SourceArtifactMapping` and `DetectorVersion`, plus the candidate-index
//! feature tables `FeatureFingerprint`, `FeatureOccurrence` and `UnitFeature`,
//! and the per-group `CloneGroupSimilarity` breakdown.
//! The artifact tables and `group_lineage` are created empty in this release —
//! the schema is the contract, population comes with the features that need
//! them.
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
//! - Savings and confidence live in separate columns; there is no single
//!   collapsed score column.
//!
//! Migrations are forward-only. `schema_meta` stores the version; opening a
//! database written by a newer tool fails with an explicit error instead of
//! guessing (downgrade is unsupported by design).

use rusqlite::Connection;

use crate::StoreError;

/// Current schema version. Bump together with an appended migration.
pub const SCHEMA_VERSION: i64 = 7;

/// Migration scripts, applied in order; index `i` migrates version `i` to
/// `i + 1`. Existing entries are frozen — schema changes append.
const MIGRATIONS: &[&str] = &[V1, V2, V3, V4, V5, V6, V7];

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
    for (i, script) in MIGRATIONS.iter().enumerate().skip(start) {
        let tx = conn.transaction()?;
        tx.execute_batch(script)?;
        let next = i64::try_from(i + 1).unwrap_or(i64::MAX);
        tx.execute(
            "INSERT INTO schema_meta (id, version) VALUES (1, ?1)
             ON CONFLICT (id) DO UPDATE SET version = excluded.version",
            [next],
        )?;
        tx.commit()?;
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
