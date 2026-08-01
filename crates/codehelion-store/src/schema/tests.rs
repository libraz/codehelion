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
INSERT INTO clone_group (id, scan_run_id, group_fingerprint_id, clone_type,
                         member_count, score, entropy_bits)
    VALUES (1, 1, 1, 'type-2', 1, 0.5, 8.0);
INSERT INTO clone_group_member (clone_group_id, fragment_id, finding_id, is_canonical)
    VALUES (1, 1, randomblob(16), 1);
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
