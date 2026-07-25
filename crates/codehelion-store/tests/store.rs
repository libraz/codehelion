//! Store integration: snapshot round-trips, crash atomicity, fingerprint
//! dedup across scans, and migration behaviour — all against real `SQLite`
//! databases (in-memory and on-disk), never mocks.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use codehelion_core::boilerplate::Boilerplate;
use codehelion_core::clone_class::CloneClass;
use codehelion_core::discovery::{BuildVariant, Language, LanguageSelection};
use codehelion_core::features::{
    ApiCallFeature, CfgFeature, CharacteristicVector, FeatureHash, FeatureKind, SubtreeFeature,
    UnitFeatures, WindowFeature,
};
use codehelion_core::frontend::UnitKind;
use codehelion_core::ir::ByteRange;
use codehelion_core::stable_id::{
    CloneGroupFingerprint, FindingId, FragmentFingerprint, UnitFingerprint,
};
use codehelion_store::snapshot::{
    FeatureRow, GroupRow, MemberRow, SimilarityBreakdownRow, Snapshot, SuppressionRuleRow, UnitRow,
};
use codehelion_store::{Store, StoreError};

const fn unit_fp(seed: u8) -> UnitFingerprint {
    UnitFingerprint::from_bytes([seed; 16])
}

const fn frag_fp(seed: u8) -> FragmentFingerprint {
    FragmentFingerprint::from_bytes([seed; 16])
}

const fn group_fp(seed: u8) -> CloneGroupFingerprint {
    CloneGroupFingerprint::from_bytes([seed; 16])
}

const fn finding(seed: u8) -> FindingId {
    FindingId::from_bytes([seed; 16])
}

fn detector_versions() -> Vec<(String, String)> {
    vec![
        ("normalization".to_string(), "2".to_string()),
        ("frontend.rust".to_string(), "rust-lexer-v0".to_string()),
        ("fp-schema".to_string(), "fp-schema-v1".to_string()),
    ]
}

fn member(seed: u8, path: &str, host: Option<usize>) -> MemberRow {
    MemberRow {
        content: frag_fp(seed),
        finding: finding(seed.wrapping_add(100)),
        language: Language::Rust,
        host_unit: host,
        file_path: path.to_string(),
        start_line: 10,
        end_line: 20,
        token_count: 42,
    }
}

fn sample_snapshot<'a>(
    variant: &'a BuildVariant,
    detectors: &'a [(String, String)],
) -> Snapshot<'a> {
    Snapshot {
        root_path: "/repo",
        tool_version: "0.1.0",
        config_hash: "cfg-hash",
        started_at: "2026-07-24T00:00:00Z",
        finished_at: "2026-07-24T00:00:05Z",
        variant,
        detector_versions: detectors,
        units: vec![
            UnitRow {
                fingerprint: unit_fp(1),
                language: Language::Rust,
                kind: UnitKind::Function,
                name: Some("checksum".to_string()),
                file_path: "src/a.rs".to_string(),
                start_line: 1,
                end_line: 9,
                token_count: 50,
            },
            UnitRow {
                fingerprint: unit_fp(1),
                language: Language::Rust,
                kind: UnitKind::Function,
                name: Some("checksum".to_string()),
                file_path: "src/b.rs".to_string(),
                start_line: 3,
                end_line: 11,
                token_count: 50,
            },
        ],
        suppressions: Vec::new(),
        groups: vec![GroupRow {
            fingerprint: group_fp(9),
            clone_type: CloneClass::Type1,
            score: 1.0,
            entropy_bits: 4.2,
            suppress_reason: None,
            boilerplate: None,
            suppressed_by: None,
            final_priority: 42.0,
            similarity: None,
            members: vec![
                member(1, "src/a.rs", Some(0)),
                member(1, "src/b.rs", Some(1)),
            ],
        }],
        features: Vec::new(),
    }
}

#[test]
fn a_snapshot_round_trips_through_queries() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let run = store.latest_run().unwrap().expect("a run");
    assert_eq!(run.id, run_id);
    assert_eq!(run.root_path, "/repo");
    assert_eq!(run.analysis_mode, "fast");
    assert_eq!(run.finished_at.as_deref(), Some("2026-07-24T00:00:05Z"));
    assert_eq!(run.group_count, 1);

    let groups = store.run_groups(run_id).unwrap();
    assert_eq!(groups.len(), 1);
    let group = &groups[0];
    assert_eq!(group.fingerprint_hex, group_fp(9).to_hex());
    assert_eq!(group.clone_type, "type-1");
    assert!(
        group.similarity.is_none(),
        "Fast mode measures no breakdown"
    );
    assert_eq!(group.members.len(), 2);
    assert_eq!(group.members[0].file_path, "src/a.rs");
    assert_eq!(group.members[0].unit_name.as_deref(), Some("checksum"));
    assert!(group.members[0].is_canonical);
    assert!(!group.members[1].is_canonical);

    // `explain` path: look one occurrence up by its finding id.
    let hex = finding(101).to_hex();
    let occurrence = store.occurrence(&hex).unwrap().expect("occurrence");
    assert_eq!(occurrence.member.finding_hex, hex);
    assert_eq!(occurrence.group_fingerprint_hex, group_fp(9).to_hex());
    assert_eq!(occurrence.scan_run_id, run_id);

    // Unknown but well-formed id: not found, not an error.
    assert!(store.occurrence(&finding(250).to_hex()).unwrap().is_none());
    // Malformed id: an explicit error.
    assert!(matches!(
        store.occurrence("not-hex"),
        Err(StoreError::MalformedId { .. })
    ));
}

#[test]
fn a_structural_group_persists_its_similarity_breakdown() {
    let variant = BuildVariant::structural(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].clone_type = CloneClass::Type2;
    snapshot.groups[0].similarity = Some(SimilarityBreakdownRow {
        weight_version: "structural-verify-v0".to_string(),
        lexical: 0.8,
        structural: 0.95,
        control_flow: 0.9,
        // Structural mode resolves no types.
        type_similarity: None,
        api: 0.5,
        composite: 0.87,
        min_pairwise: 0.72,
    });
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let breakdown = groups[0]
        .similarity
        .as_ref()
        .expect("the structural group carries a breakdown");
    assert_eq!(breakdown.weight_version, "structural-verify-v0");
    assert!((breakdown.structural - 0.95).abs() < 1e-9);
    assert!((breakdown.composite - 0.87).abs() < 1e-9);
    assert!((breakdown.min_pairwise - 0.72).abs() < 1e-9);
    // The unmeasured type dimension survives the round-trip as absent.
    assert!(breakdown.type_similarity.is_none());
}

#[test]
fn a_boilerplate_group_records_what_it_is_independently_of_policy() {
    let variant = BuildVariant::structural(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].boilerplate = Some(Boilerplate::MacroRepetition);
    // Nothing was suppressed: the classification is a fact about the code,
    // not a record of what the report did with it.
    snapshot.groups[0].suppress_reason = None;
    snapshot.groups[0].suppressed_by = None;
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    assert_eq!(groups[0].boilerplate.as_deref(), Some("macro-repetition"));
    assert!(groups[0].suppress_reason.is_none());

    // A group that matches no shape stores none.
    let mut plain = sample_snapshot(&variant, &detectors);
    plain.groups[0].boilerplate = None;
    let run_id = store.record_snapshot(&plain).unwrap();
    assert!(store.run_groups(run_id).unwrap()[0].boilerplate.is_none());
}

#[test]
fn a_failing_snapshot_leaves_no_partial_rows() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    // A member referencing a unit index that does not exist fails the write
    // midway, after the run and unit rows were already inserted.
    snapshot.groups[0].members[1].host_unit = Some(99);
    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnknownUnitIndex { index: 99, .. }
    ));

    assert!(store.latest_run().unwrap().is_none(), "no partial run");
    for table in [
        "scan_run",
        "source_unit",
        "fragment",
        "clone_group",
        "finding",
        "fingerprint",
    ] {
        let count = store.table_count(table).unwrap();
        assert_eq!(count, 0, "table {table} must be empty after rollback");
    }
}

#[test]
fn fingerprints_deduplicate_across_scans_but_runs_do_not() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let mut second = sample_snapshot(&variant, &detectors);
    second.started_at = "2026-07-25T00:00:00Z";
    second.finished_at = "2026-07-25T00:00:04Z";
    let second_id = store.record_snapshot(&second).unwrap();

    assert_eq!(store.table_count("scan_run").unwrap(), 2);
    // Identical content under an identical context: one fingerprint row per
    // identity (1 unit + 1 member content + 1 group), not per scan.
    assert_eq!(store.table_count("fingerprint").unwrap(), 3);
    assert_eq!(store.table_count("build_variant").unwrap(), 1);

    // The later run is the latest.
    assert_eq!(store.latest_run().unwrap().unwrap().id, second_id);
}

/// A unit-features fixture with one window, one subtree, a cfg profile and
/// the two api hashes — five distinct feature hashes in total.
fn sample_unit_features() -> UnitFeatures {
    let mut counts = [0u32; 23];
    counts[1] = 3;
    counts[11] = 2;
    UnitFeatures {
        name: None,
        shape_tag: 1,
        range: ByteRange { start: 0, end: 100 },
        windows: vec![WindowFeature {
            hash: FeatureHash::from_bytes([7; 16]),
            length: 4,
            range: ByteRange { start: 0, end: 40 },
        }],
        subtrees: vec![SubtreeFeature {
            hash: FeatureHash::from_bytes([8; 16]),
            node_count: 6,
            range: ByteRange { start: 0, end: 50 },
        }],
        vector: CharacteristicVector {
            counts,
            max_depth: 4,
            node_count: 12,
        },
        cfg: CfgFeature {
            hash: FeatureHash::from_bytes([9; 16]),
            op_count: 5,
            max_loop_depth: 2,
            branch_count: 1,
        },
        api: ApiCallFeature {
            names: Vec::new(),
            sequence_hash: FeatureHash::from_bytes([10; 16]),
            multiset_hash: FeatureHash::from_bytes([11; 16]),
        },
    }
}

#[test]
fn feature_fingerprints_persist_and_deduplicate_across_scans() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let unit = sample_unit_features();
    let mut first = sample_snapshot(&variant, &detectors);
    first.features = vec![FeatureRow::from_unit(0, &unit)];
    let run_id = store.record_snapshot(&first).unwrap();

    // One window + one subtree + one cfg + two api hashes = five occurrences,
    // each a distinct fingerprint; one scalar unit_feature row.
    assert_eq!(store.table_count("feature_occurrence").unwrap(), 5);
    assert_eq!(store.table_count("feature_fingerprint").unwrap(), 5);
    assert_eq!(store.table_count("unit_feature").unwrap(), 1);

    // The subtree hash resolves to its single occurrence with the right anchor
    // and extent.
    let posting = store
        .feature_posting_list(FeatureKind::Subtree, &[8; 16])
        .unwrap();
    assert_eq!(posting.len(), 1);
    assert_eq!(posting[0].scan_run_id, run_id);
    assert_eq!(posting[0].start_byte, 0);
    assert_eq!(posting[0].end_byte, 50);
    assert_eq!(posting[0].extent, 6);
    assert!(posting[0].source_unit_id.is_some());
    assert!(
        store
            .feature_posting_list(FeatureKind::Subtree, &[99; 16])
            .unwrap()
            .is_empty()
    );

    // A second, identical scan reuses every fingerprint row but records fresh
    // occurrences and a fresh unit_feature row.
    let mut second = sample_snapshot(&variant, &detectors);
    second.started_at = "2026-07-25T00:00:00Z";
    second.finished_at = "2026-07-25T00:00:04Z";
    second.features = vec![FeatureRow::from_unit(0, &unit)];
    store.record_snapshot(&second).unwrap();
    assert_eq!(store.table_count("feature_fingerprint").unwrap(), 5);
    assert_eq!(store.table_count("feature_occurrence").unwrap(), 10);
    assert_eq!(store.table_count("unit_feature").unwrap(), 2);
    assert_eq!(
        store
            .feature_posting_list(FeatureKind::Subtree, &[8; 16])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_feature_referencing_an_unknown_unit_rolls_the_snapshot_back() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let unit = sample_unit_features();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.features = vec![FeatureRow::from_unit(99, &unit)];
    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnknownUnitIndex { index: 99, .. }
    ));

    assert!(store.latest_run().unwrap().is_none(), "no partial run");
    for table in ["feature_fingerprint", "feature_occurrence", "unit_feature"] {
        assert_eq!(store.table_count(table).unwrap(), 0, "{table} not empty");
    }
}

#[test]
fn artifact_and_lineage_tables_exist_and_stay_empty() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    for table in [
        "artifact",
        "artifact_symbol",
        "source_artifact_mapping",
        "group_lineage",
    ] {
        assert_eq!(
            store.table_count(table).unwrap(),
            0,
            "{table} must stay empty"
        );
    }
    // The diagnostic rejects unknown tables instead of interpolating them.
    assert!(matches!(
        store.table_count("no_such_table"),
        Err(StoreError::UnknownTable { .. })
    ));
}

#[test]
fn findings_start_in_the_new_state() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();
    let findings = store.run_findings(run_id).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].audit_state, "new");
    assert_eq!(findings[0].group_fingerprint_hex, group_fp(9).to_hex());
    assert!((findings[0].clone_confidence - 1.0).abs() < f64::EPSILON);
    assert!((findings[0].final_priority - 42.0).abs() < f64::EPSILON);
    assert!(findings[0].suppression_scope.is_none());
}

#[test]
fn suppressed_findings_reference_a_deduplicated_rule_row() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: Some("vendored sources".to_string()),
    }];
    snapshot.groups[0].suppressed_by = Some(0);
    let first_run = store.record_snapshot(&snapshot).unwrap();
    let second_run = store.record_snapshot(&snapshot).unwrap();
    assert_ne!(first_run, second_run);

    // One rule row serves both runs' findings.
    assert_eq!(store.table_count("suppression").unwrap(), 1);
    for run_id in [first_run, second_run] {
        let findings = store.run_findings(run_id).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].suppression_scope.as_deref(), Some("path_glob"));
    }
}

#[test]
fn an_unknown_suppression_index_rolls_the_snapshot_back() {
    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].suppressed_by = Some(5);
    let err = store.record_snapshot(&snapshot).unwrap_err();
    assert!(matches!(
        err,
        StoreError::UnknownSuppressionIndex { index: 5, rules: 0 }
    ));
    assert!(store.latest_run().unwrap().is_none(), "no partial run");
}

#[test]
fn on_disk_databases_reopen_and_a_newer_schema_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");

    let variant = BuildVariant::fast(LanguageSelection::default());
    let detectors = detector_versions();
    {
        let mut store = Store::open(&path).unwrap();
        store
            .record_snapshot(&sample_snapshot(&variant, &detectors))
            .unwrap();
    }
    {
        // Reopen: migration is idempotent and the data is still there.
        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.schema_version().unwrap(),
            codehelion_store::schema::SCHEMA_VERSION
        );
        assert!(store.latest_run().unwrap().is_some());
    }

    // Pretend a newer tool wrote the database.
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE schema_meta SET version = 999", [])
            .unwrap();
    }
    let err = Store::open(&path).unwrap_err();
    assert!(matches!(
        err,
        StoreError::SchemaTooNew {
            found: 999,
            supported: _
        }
    ));
}
