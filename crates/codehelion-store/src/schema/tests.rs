use super::*;

/// One group with one member, and the chain of rows they need to exist.
///
/// Every insert names its columns. Positional inserts would tie the seed to
/// how wide each table happens to be when it is written, so additions do
/// not silently make a fixture describe a different baseline.
const SEED: &str = "
INSERT INTO build_variant (id, variant_fingerprint, canonical, analysis_mode,
                           normalization_version)
    VALUES (1, 'v', 'canonical', 'structural', 1);
INSERT INTO scan_run (id, build_variant_id, root_path, tool_version, config_hash,
                      config_source, analysis_mode, started_at, min_clone_tokens, status)
    VALUES (1, 1, '/tree', '0.1.0', 'cfg', 'defaults', 'structural',
            '2026-01-01T00:00:00Z', 20, 'completed');
INSERT INTO fingerprint (id, kind, hash_algo, hash, normalization_version,
                         frontend_version, analysis_mode, language, build_variant_id)
    VALUES (1, 'clone_group', 'blake3', randomblob(16), 1, '', 'structural', '', 1),
           (2, 'fragment', 'blake3', randomblob(16), 1, 'f1', 'structural', 'rust', 1);
INSERT INTO fragment (id, scan_run_id, fingerprint_id, fragment_kind, file_path,
                      start_line, end_line, token_count)
    VALUES (1, 1, 2, 'function_body', 'src/lib.rs', 1, 9, 40);
INSERT INTO clone_group (id, scan_run_id, group_fingerprint_id, lineage, lineage_state,
                         clone_type, member_count, score, entropy_bits)
    VALUES (1, 1, 1, randomblob(16), 'new', 'type-2', 1, 0.5, 8.0);
INSERT INTO clone_group_member (clone_group_id, scan_run_id, fragment_id, finding_id, is_canonical)
    VALUES (1, 1, 1, randomblob(16), 1);
";

/// A current baseline database seeded with a group and its one member.
fn seeded() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY CHECK (id = 1),
                                       version INTEGER NOT NULL) STRICT;",
    )
    .unwrap();
    apply_baseline(&mut conn).unwrap();
    conn.execute_batch(SEED).unwrap();
    conn
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

/// Seed the source-unit foreign key required by `clone_group_sibling` checks.
fn sibling_ready() -> Connection {
    let conn = seeded();
    conn.execute(
        "INSERT INTO fingerprint
             (id, kind, hash_algo, hash, normalization_version, frontend_version,
              analysis_mode, language, build_variant_id)
         VALUES (3, 'unit', 'blake3', randomblob(16), 1, 'unit-v1',
                 'structural', 'rust', 1)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO source_unit
             (id, scan_run_id, fingerprint_id, language, unit_kind, name,
              file_path, start_line, end_line, token_count)
         VALUES (1, 1, 3, 'rust', 'function', 'sibling', 'src/sibling.rs', 1, 4, 20)",
        [],
    )
    .unwrap();
    conn
}

fn insert_sibling(
    conn: &Connection,
    basis: &str,
    signature: Option<&str>,
    signature_units: Option<i64>,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO clone_group_sibling
             (clone_group_id, scan_run_id, source_unit_id, fragment_fingerprint,
              finding_id, basis, signature, signature_units, clone_type, confidence_band,
              weight_version, lexical, structural, composite)
         VALUES (1, 1, 1, randomblob(16), randomblob(16), ?1, ?2, ?3,
                 'type-3', 'low', 'test-v1', 0.1, 0.2, 0.15)",
        rusqlite::params![basis, signature, signature_units],
    )
}

#[test]
fn sibling_basis_and_signature_checks_reject_inconsistent_raw_rows() {
    let valid_similarity = sibling_ready();
    assert_eq!(
        insert_sibling(&valid_similarity, "similarity", None, None).unwrap(),
        1
    );

    let valid_signature = sibling_ready();
    assert_eq!(
        insert_sibling(
            &valid_signature,
            "signature",
            Some("signature-sentinel"),
            Some(3)
        )
        .unwrap(),
        1
    );

    for (basis, signature) in [
        ("similarity", Some("must-be-null")),
        ("signature", None),
        ("signature", Some("")),
    ] {
        let conn = sibling_ready();
        let units = signature.map(|_| 3);
        assert!(
            insert_sibling(&conn, basis, signature, units).is_err(),
            "inconsistent sibling row unexpectedly inserted: basis={basis:?}, signature={signature:?}"
        );
    }
}

/// The sharing count belongs to the signature channel exactly like the
/// signature itself: required with it, absent without it.
#[test]
fn sibling_signature_unit_count_is_tied_to_the_signature_channel() {
    for (basis, signature, signature_units) in [
        ("signature", Some("signature-sentinel"), None),
        ("similarity", None, Some(3)),
    ] {
        let conn = sibling_ready();
        assert!(
            insert_sibling(&conn, basis, signature, signature_units).is_err(),
            "sibling row with a mismatched sharing count unexpectedly inserted: \
             basis={basis:?}, signature_units={signature_units:?}"
        );
    }
}

/// A count of units sharing a signature cannot be negative.
#[test]
fn sibling_signature_unit_count_rejects_a_negative_count() {
    let conn = sibling_ready();
    assert!(
        insert_sibling(&conn, "signature", Some("signature-sentinel"), Some(-1)).is_err(),
        "negative signature sharing count unexpectedly inserted"
    );
}

/// A freshly created database records the baseline this build writes.
#[test]
fn baseline_creation_records_the_version_this_build_writes() {
    let conn = seeded();
    assert_eq!(version(&conn).unwrap(), SCHEMA_VERSION);
    assert_eq!(SCHEMA_VERSION, 6);
}

/// A database recorded before this baseline is refused rather than read.
///
/// This baseline added tables that such a database does not have, and nothing
/// migrates one layout into the other. The recorded version is what turns that
/// away at open time; without it, a report would reach a table its database was
/// never created with, mid-read.
#[test]
fn a_database_recorded_before_this_baseline_is_refused_rather_than_read() {
    let conn = seeded();
    // The previous layout, reproduced by removing exactly what this one added.
    conn.execute_batch(
        "DROP TABLE seam_run_entry;
         DROP TABLE seam_run;",
    )
    .unwrap();
    conn.execute("UPDATE schema_meta SET version = ?1", [SCHEMA_VERSION - 1])
        .unwrap();

    let error = validate_existing(&conn).unwrap_err();
    assert!(
        matches!(error, StoreError::UnsupportedSchema { found } if found == SCHEMA_VERSION - 1),
        "{error:?}"
    );
    assert!(
        conn.prepare("SELECT ordinal FROM seam_run_entry WHERE seam_run_id = ?1")
            .is_err(),
        "the previous layout answered a read only this baseline can answer"
    );
}

/// Creating the baseline under enforced foreign keys leaves its seeded
/// relation rows intact.
#[test]
fn baseline_creation_keeps_related_rows() {
    let mut conn = seeded();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    initialize(&mut conn).unwrap();
    assert_eq!(count(&conn, "clone_group"), 1);
    assert_eq!(count(&conn, "clone_group_member"), 1);
}

/// Baseline creation restores the caller's foreign-key setting.
#[test]
fn baseline_creation_leaves_foreign_keys_as_it_found_them() {
    let mut conn = seeded();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    initialize(&mut conn).unwrap();
    let enforced: i64 = conn
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .unwrap();
    assert_eq!(enforced, 1);
}

#[test]
fn clone_fragment_reverse_lookup_uses_its_dedicated_index() {
    let conn = seeded();
    let mut statement = conn
        .prepare(
            "EXPLAIN QUERY PLAN
                 SELECT clone_group_id
                 FROM clone_group_member
                 WHERE fragment_id = ?1",
        )
        .unwrap();
    let plan = statement
        .query_map([1_i64], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("idx_clone_group_member_fragment")),
        "the reverse lookup does not use its index: {plan:?}"
    );
}

#[test]
fn artifact_fragment_mapping_lookup_uses_its_dedicated_index() {
    let conn = seeded();
    let mut statement = conn
        .prepare(
            "EXPLAIN QUERY PLAN
                 SELECT artifact_analysis_id
                 FROM artifact_analysis_source_mapping
                 WHERE source_kind = 'fragment' AND source_instance_fingerprint = ?1",
        )
        .unwrap();
    let plan = statement
        .query_map([vec![0_u8; 16]], |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("idx_artifact_analysis_mapping_fragment_instance")),
        "the finding mapping lookup does not use its index: {plan:?}"
    );
}

#[test]
fn artifact_tables_accept_only_the_canonical_format_vocabulary() {
    let conn = seeded();
    for (id, format) in ["wasm", "elf", "macho", "pe-coff", "archive"]
        .into_iter()
        .enumerate()
    {
        conn.execute(
            "INSERT INTO artifact
                     (scan_run_id, build_variant_id, format, path, total_size_bytes, content_hash)
                 VALUES (1, 1, ?1, ?2, 1, 'fixture')",
            (format, format!("fixture-{id}")),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO artifact_analysis
                     (schema_version, path, format, content_fingerprint, observed_bytes,
                      started_at, finished_at, status)
                 VALUES ('fixture-v1', ?1, ?2, randomblob(16), 1,
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'completed')",
            (format!("fixture-{id}"), format),
        )
        .unwrap();
    }

    for legacy_format in ["pecoff", "object"] {
        assert!(
                conn.execute(
                    "INSERT INTO artifact
                         (scan_run_id, build_variant_id, format, path, total_size_bytes, content_hash)
                     VALUES (1, 1, ?1, 'legacy', 1, 'fixture')",
                    [legacy_format],
                )
                .is_err()
            );
    }
    assert!(
        conn.execute(
            "INSERT INTO artifact_analysis
                     (schema_version, path, format, content_fingerprint, observed_bytes,
                      started_at, finished_at, status)
                 VALUES ('fixture-v1', 'legacy', 'mach-o', randomblob(16), 1,
                         '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'completed')",
            [],
        )
        .is_err()
    );
}

/// Every reason a helper can report has to be writable. A reason the code
/// produces but the column refuses takes down the transaction that carries it,
/// and with it every unit the same scan already analysed.
#[test]
fn the_unit_reason_column_accepts_every_reason_a_helper_can_report() {
    let conn = seeded();
    for (id, reason) in Unavailability::ALL.into_iter().enumerate() {
        conn.execute(
            "INSERT INTO compiler_unit
                 (scan_run_id, build_variant_id, unit_name, file_path, variant_key,
                  unavailable_reason, has_cfg, effects_computed, data_flow_computed)
             VALUES (1, 1, ?1, 'src/lib.rs', 'v', ?2, 0, 0, 0)",
            (format!("unit-{id}"), reason.name()),
        )
        .unwrap_or_else(|error| panic!("{} was refused: {error}", reason.name()));
    }
    assert_eq!(
        count(&conn, "compiler_unit"),
        i64::try_from(Unavailability::ALL.len()).unwrap()
    );
    assert!(
        conn.execute(
            "INSERT INTO compiler_unit
                 (scan_run_id, build_variant_id, unit_name, file_path, variant_key,
                  unavailable_reason, has_cfg, effects_computed, data_flow_computed)
             VALUES (1, 1, 'invented', 'src/lib.rs', 'v', 'no_such_reason', 0, 0, 0)",
            [],
        )
        .is_err(),
        "a reason no build produces was accepted"
    );
}

/// The same for the artifact reader: a binary whose debug information cannot
/// be decoded is the input it exists to survive, and recording why a symbol
/// stayed unmapped must not discard the rest of the analysis.
#[test]
fn the_unmapped_columns_accept_every_reason_correlation_can_establish() {
    let conn = seeded();
    conn.execute(
        "INSERT INTO artifact_analysis
             (id, schema_version, path, format, content_fingerprint, observed_bytes,
              started_at, finished_at, status)
         VALUES (1, 'fixture-v1', 'lib.wasm', 'wasm', randomblob(16), 1,
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'completed')",
        [],
    )
    .unwrap();
    for (id, reason) in ArtifactAnalysisUnmappedReason::ALL.into_iter().enumerate() {
        conn.execute(
            "INSERT INTO artifact_analysis_unmapped_symbol
                 (artifact_analysis_id, artifact_symbol_fingerprint, reason)
             VALUES (1, ?1, ?2)",
            (vec![u8::try_from(id).unwrap(); 16], reason.as_sql()),
        )
        .unwrap_or_else(|error| panic!("{} was refused: {error}", reason.as_sql()));
    }
    for (id, reason) in ArtifactAnalysisUnmappedSourceReason::ALL
        .into_iter()
        .enumerate()
    {
        conn.execute(
            "INSERT INTO artifact_analysis_unmapped_source
                 (artifact_analysis_id, source_kind, source_fingerprint,
                  source_instance_fingerprint, reason)
             VALUES (1, 'unit', ?1, ?1, ?2)",
            (vec![u8::try_from(id).unwrap(); 16], reason.as_sql()),
        )
        .unwrap_or_else(|error| panic!("{} was refused: {error}", reason.as_sql()));
    }
    assert_eq!(
        count(&conn, "artifact_analysis_unmapped_symbol"),
        i64::try_from(ArtifactAnalysisUnmappedReason::ALL.len()).unwrap()
    );
    assert_eq!(
        count(&conn, "artifact_analysis_unmapped_source"),
        i64::try_from(ArtifactAnalysisUnmappedSourceReason::ALL.len()).unwrap()
    );
    assert!(
        conn.execute(
            "INSERT INTO artifact_analysis_unmapped_symbol
                 (artifact_analysis_id, artifact_symbol_fingerprint, reason)
             VALUES (1, randomblob(16), 'no_such_reason')",
            [],
        )
        .is_err(),
        "a reason no build produces was accepted"
    );
}

/// A declared source-map reference that did not resolve is evidence too, so
/// every reason the analysis can establish has to be writable — and a
/// resolution that claims to be both resolved and unavailable has to not be.
#[test]
fn the_source_map_resolution_column_accepts_every_reason_an_analysis_can_establish() {
    let conn = seeded();
    conn.execute(
        "INSERT INTO artifact_analysis
             (id, schema_version, path, format, content_fingerprint, observed_bytes,
              started_at, finished_at, status)
         VALUES (1, 'fixture-v1', 'lib.wasm', 'wasm', randomblob(16), 1,
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', 'completed')",
        [],
    )
    .unwrap();
    for (ordinal, reason) in ArtifactAnalysisSourceMapReason::ALL.into_iter().enumerate() {
        conn.execute(
            "INSERT INTO artifact_analysis_source_map_resolution
                 (artifact_analysis_id, ordinal, uri, local_path, reason)
             VALUES (1, ?1, 'module.wasm.map', NULL, ?2)",
            (i64::try_from(ordinal).unwrap(), reason.as_sql()),
        )
        .unwrap_or_else(|error| panic!("{} was refused: {error}", reason.as_sql()));
    }
    assert_eq!(
        count(&conn, "artifact_analysis_source_map_resolution"),
        i64::try_from(ArtifactAnalysisSourceMapReason::ALL.len()).unwrap()
    );
    assert!(
        conn.execute(
            "INSERT INTO artifact_analysis_source_map_resolution
                 (artifact_analysis_id, ordinal, uri, local_path, reason)
             VALUES (1, 100, 'module.wasm.map', NULL, 'no_such_reason')",
            [],
        )
        .is_err(),
        "a reason no build produces was accepted"
    );
    for (local_path, reason) in [
        (None, None),
        (Some("/fixtures/module.wasm.map"), Some("map_not_found")),
    ] {
        assert!(
            conn.execute(
                "INSERT INTO artifact_analysis_source_map_resolution
                     (artifact_analysis_id, ordinal, uri, local_path, reason)
                 VALUES (1, 101, 'module.wasm.map', ?1, ?2)",
                (local_path, reason),
            )
            .is_err(),
            "a resolution that is neither exactly resolved nor exactly unavailable was accepted: \
             local_path={local_path:?}, reason={reason:?}"
        );
    }
}

/// A rule is content-addressed by what it matches, so two rows can never claim
/// the same pair: one lookup would find either of them and an update would
/// flip only one.
#[test]
fn a_suppression_rule_exists_at_most_once_per_scope_and_pattern() {
    let conn = seeded();
    let insert = |reason: &str| {
        conn.execute(
            "INSERT INTO suppression (scope, pattern, reason, active)
             VALUES ('path_glob', 'vendor/**', ?1, 1)",
            [reason],
        )
    };
    assert_eq!(insert("first").unwrap(), 1);
    assert!(
        insert("second").is_err(),
        "a second row for one rule was accepted"
    );
    assert_eq!(count(&conn, "suppression"), 1);
}

/// Resolving a lineage edge names the kind it is looking for, so it reaches
/// the declared index instead of reading every fingerprint in the database —
/// and cannot answer with a row from another identifier namespace.
#[test]
fn lineage_group_lookup_is_constrained_to_group_fingerprints() {
    let conn = seeded();
    let mut statement = conn
        .prepare(
            "EXPLAIN QUERY PLAN
                 SELECT g.id FROM clone_group g
                 JOIN fingerprint f ON f.id = g.group_fingerprint_id
                 WHERE g.scan_run_id = ?1 AND f.kind = 'clone_group' AND f.hash = ?2",
        )
        .unwrap();
    let plan = statement
        .query_map((1_i64, vec![0_u8; 16]), |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        plan.iter()
            .any(|step| step.contains("idx_fingerprint_kind_hash")),
        "the lineage lookup does not use the declared index: {plan:?}"
    );
    assert!(
        !plan.iter().any(|step| step.contains("SCAN fingerprint")),
        "the lineage lookup reads every fingerprint: {plan:?}"
    );
}
