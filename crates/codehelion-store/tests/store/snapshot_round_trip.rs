use super::*;

#[test]
fn a_snapshot_round_trips_through_queries() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
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
    assert_eq!(
        store.run_group_ranked_down(run_id).unwrap(),
        std::collections::BTreeMap::from([(group_fp(9).to_hex(), true)])
    );
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
fn a_sibling_round_trips_without_becoming_a_primary_member() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: Some("vendored sources".to_string()),
    }];
    snapshot.units.push(UnitRow {
        fingerprint: unit_fp(2),
        language: Language::Rust,
        kind: UnitKind::Function,
        name: Some("incomplete_checksum".to_string()),
        file_path: "src/c.rs".to_string(),
        start_line: 30,
        end_line: 36,
        token_count: 31,
    });
    snapshot.units.push(UnitRow {
        fingerprint: unit_fp(3),
        language: Language::Rust,
        kind: UnitKind::Function,
        name: Some("similarity_checksum".to_string()),
        file_path: "src/d.rs".to_string(),
        start_line: 40,
        end_line: 46,
        token_count: 29,
    });
    snapshot.sibling_groups.push(SiblingGroupRow {
        group: group_fp(9),
        siblings: vec![
            SiblingRow {
                unit: 2,
                content: frag_fp(2),
                finding: finding(203),
                basis: SiblingBasis::Signature,
                signature: Some("rust|params=[]|return=()".to_string()),
                clone_type: CloneClass::Type3,
                confidence: Confidence::Low,
                similarity: SimilarityBreakdownRow {
                    weight_version: "structural-verify-v1".to_string(),
                    lexical: 0.72,
                    structural: 0.91,
                    control_flow: Some(0.8),
                    type_similarity: None,
                    api: Some(0.7),
                    composite: 0.76,
                    min_pairwise: 0.76,
                    confidence_band: Confidence::Low,
                },
                boilerplate: None,
                suppressed_by: Some(0),
            },
            SiblingRow {
                unit: 3,
                content: frag_fp(3),
                finding: finding(204),
                basis: SiblingBasis::Similarity,
                signature: None,
                clone_type: CloneClass::Type3,
                confidence: Confidence::Medium,
                similarity: SimilarityBreakdownRow {
                    weight_version: "structural-verify-v1".to_string(),
                    lexical: 0.42,
                    structural: 0.55,
                    control_flow: None,
                    type_similarity: None,
                    api: Some(0.31),
                    composite: 0.42,
                    min_pairwise: 0.42,
                    confidence_band: Confidence::Medium,
                },
                boilerplate: None,
                suppressed_by: Some(0),
            },
        ],
    });
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    assert_eq!(groups[0].members.len(), 2);
    assert_eq!(groups[0].siblings.len(), 2);
    let sibling = &groups[0].siblings[0];
    assert_eq!(sibling.member.file_path, "src/c.rs");
    assert_eq!(
        sibling.member.unit_name.as_deref(),
        Some("incomplete_checksum")
    );
    assert_eq!(sibling.member.finding_hex, finding(203).to_hex());
    assert_eq!(sibling.clone_type, "type-3");
    assert_eq!(sibling.confidence_band, "low");
    assert_eq!(sibling.basis, "signature");
    assert_eq!(
        sibling.signature.as_deref(),
        Some("rust|params=[]|return=()")
    );
    assert!((sibling.composite - 0.76).abs() < f64::EPSILON);
    let rule = sibling
        .suppressed_by
        .as_ref()
        .expect("the sibling retains its suppression rule");
    assert_eq!(rule.scope, "path_glob");
    assert_eq!(rule.pattern, "vendor/**");

    let similarity = &groups[0].siblings[1];
    assert_eq!(similarity.member.file_path, "src/d.rs");
    assert_eq!(similarity.basis, "similarity");
    assert!(similarity.signature.is_none());
    assert!((similarity.composite - 0.42).abs() < f64::EPSILON);

    let explained = store
        .sibling(&finding(203).to_hex())
        .unwrap()
        .expect("sibling id resolves");
    assert_eq!(explained.run_id, run_id);
    assert_eq!(explained.group_fingerprint_hex, group_fp(9).to_hex());
    assert_eq!(&explained.sibling, sibling);
    assert_eq!(
        store.ids_starting_with(&finding(203).to_hex()).unwrap(),
        vec![IdMatch {
            kind: IdKind::Sibling,
            id: finding(203).to_hex(),
        }]
    );
    let explained_similarity = store
        .sibling(&finding(204).to_hex())
        .unwrap()
        .expect("similarity sibling id resolves");
    assert_eq!(explained_similarity.sibling.basis, "similarity");
    assert!(explained_similarity.sibling.signature.is_none());
    assert!((explained_similarity.sibling.composite - 0.42).abs() < f64::EPSILON);
}

#[test]
fn a_near_miss_round_trips_without_becoming_a_primary_finding() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![SuppressionRuleRow {
        scope: "path_glob".to_string(),
        pattern: "vendor/**".to_string(),
        reason: Some("vendored sources".to_string()),
    }];
    snapshot.near_misses.push(NearMissRow {
        left: 0,
        right: 1,
        estimated_jaccard: 0.28,
        suppressed_by: Some(0),
    });
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let near_misses = store.run_near_misses(run_id).unwrap();
    assert_eq!(near_misses.len(), 1);
    let near_miss = &near_misses[0];
    assert!((near_miss.estimated_jaccard - 0.28).abs() < f64::EPSILON);
    assert_eq!(near_miss.left.file_path, "src/a.rs");
    assert_eq!(near_miss.right.file_path, "src/b.rs");
    assert_eq!(near_miss.left.unit_name.as_deref(), Some("checksum"));
    assert_eq!(near_miss.right.unit_name.as_deref(), Some("checksum"));
    let rule = near_miss
        .suppressed_by
        .as_ref()
        .expect("the near miss retains its suppression rule");
    assert_eq!(rule.scope, "path_glob");
    assert_eq!(rule.pattern, "vendor/**");

    let groups = store.run_groups(run_id).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].members.len(), 2);
    assert!(groups[0].siblings.is_empty());
}
/// What a run reported about itself has to come back the way it went in,
/// stage order and drop order included: a report rebuilt from these rows is
/// compared byte for byte against the one the scan printed.
#[test]
fn what_a_run_reported_about_itself_comes_back_as_it_went_in() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let read = store.run_summary_row(run_id).unwrap().expect("a summary");
    assert_eq!(read, sample_summary());
}

#[test]
fn source_units_keep_the_variant_that_minted_their_fingerprints() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let units = store.source_units(run_id).unwrap();
    assert_eq!(units.len(), 2);
    assert_eq!(units[0].file_path, "src/a.rs");
    assert_eq!(units[0].fingerprint, [1; 16]);
    assert_eq!(units[0].start_line, Some(1));
    assert_eq!(units[0].end_line, Some(9));
    assert_eq!(
        units[0].build_variant_fingerprint,
        units[1].build_variant_fingerprint
    );
}

#[test]
fn source_units_assign_occurrence_ordinals_without_using_line_anchors() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.units.push(UnitRow {
        fingerprint: unit_fp(1),
        language: Language::Rust,
        kind: UnitKind::Function,
        name: Some("checksum".to_string()),
        file_path: "src/a.rs".to_string(),
        start_line: 40,
        end_line: 48,
        token_count: 50,
    });
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let units = store.source_units(run_id).unwrap();
    let same_declaration: Vec<_> = units
        .iter()
        .filter(|unit| unit.file_path == "src/a.rs" && unit.name.as_deref() == Some("checksum"))
        .collect();
    assert_eq!(same_declaration.len(), 2);
    assert_eq!(same_declaration[0].unit_kind, "function");
    assert_eq!(same_declaration[0].occurrence_ordinal, 1);
    assert_eq!(same_declaration[1].occurrence_ordinal, 2);
    assert_eq!(same_declaration[0].start_line, Some(1));
    assert_eq!(same_declaration[1].start_line, Some(40));
}

#[test]
fn repeated_snapshot_rows_preserve_every_entry() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.units.push(UnitRow {
        fingerprint: unit_fp(3),
        language: Language::C,
        kind: UnitKind::Function,
        name: Some("third_checksum".to_string()),
        file_path: "src/c.c".to_string(),
        start_line: 50,
        end_line: 58,
        token_count: 60,
    });
    snapshot.files.push(FileRow {
        relative_path: "src/c.c".to_string(),
        content_hash: "cc".repeat(32),
        language: Language::C,
        byte_len: 360,
    });
    snapshot.summary.funnel.push(FunnelStageRow {
        name: "verification".to_string(),
        passed: 3,
        dropped: vec![
            FunnelDropRow {
                cause: "threshold".to_string(),
                count: 2,
            },
            FunnelDropRow {
                cause: "budget".to_string(),
                count: 1,
            },
        ],
    });
    snapshot.summary.unused_suppressions.push(UnusedRuleRow {
        scope: "fingerprint".to_string(),
        pattern: "deadbeef".to_string(),
    });
    let expected_summary = snapshot.summary.clone();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store.record_snapshot(&snapshot).unwrap();

    assert_eq!(store.source_units(run_id).unwrap().len(), 3);
    assert_eq!(
        store.run_tree(run_id).unwrap(),
        std::collections::BTreeMap::from([
            ("src/a.rs".to_string(), "aa".repeat(32)),
            ("src/b.rs".to_string(), "bb".repeat(32)),
            ("src/c.c".to_string(), "cc".repeat(32)),
        ])
    );
    assert_eq!(
        store.run_summary_row(run_id).unwrap().as_ref(),
        Some(&expected_summary)
    );
}

#[test]
fn clone_fragments_keep_the_variant_that_minted_their_fingerprints() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run_id = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let fragments = store.source_clone_fragments(run_id).unwrap();
    assert_eq!(fragments.len(), 2);
    assert_eq!(fragments[0].fingerprint, [1; 16]);
    assert_eq!(fragments[0].finding_id, [101; 16]);
    assert_eq!(fragments[0].clone_group_fingerprint, [9; 16]);
    assert!(fragments[0].is_canonical);
    assert!((fragments[0].clone_confidence - 1.0).abs() < f64::EPSILON);
    assert_eq!(fragments[0].file_path, "src/a.rs");
    assert_eq!(fragments[0].start_line, Some(10));
    assert_eq!(fragments[0].end_line, Some(20));
    assert_eq!(fragments[1].fingerprint, [1; 16]);
    assert_eq!(fragments[1].finding_id, [102; 16]);
    assert_eq!(fragments[1].clone_group_fingerprint, [9; 16]);
    assert!(!fragments[1].is_canonical);
    assert_eq!(fragments[1].file_path, "src/b.rs");
}

/// Any layout marker other than the baseline this build reads is rejected.
#[test]
fn a_database_recorded_under_another_layout_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    {
        let mut store = Store::open(&path).unwrap();
        store
            .record_snapshot(&sample_snapshot(&variant, &detectors))
            .unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE schema_meta SET version = 99", [])
            .unwrap();
    }

    assert!(matches!(
        Store::open(&path),
        Err(StoreError::UnsupportedSchema { found: 99 })
    ));
}

#[test]
fn a_group_can_be_read_by_its_fingerprint_and_found_by_an_abbreviation() {
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();
    let run = store
        .record_snapshot(&sample_snapshot(&variant, &detectors))
        .unwrap();

    let expected = &store.run_groups(run).unwrap()[0];
    let fingerprint = expected.fingerprint_hex.clone();
    let members = expected.members.len();
    let finding = expected.members[0].finding_hex.clone();

    // The same group the run lists, read on its own: what a report prints as
    // a heading has to be usable to ask about that heading.
    let found = store
        .group(&fingerprint)
        .unwrap()
        .expect("the group the run recorded");
    assert_eq!(found.run_id, run);
    assert_eq!(found.group.members.len(), members);

    assert!(store.group(&"f".repeat(32)).unwrap().is_none());

    // Both id kinds answer to an abbreviation, and each says which it is.
    let group_matches = store.ids_starting_with(&fingerprint[..12]).unwrap();
    assert_eq!(group_matches.len(), 1);
    assert_eq!(group_matches[0].kind, IdKind::CloneGroup);
    assert_eq!(group_matches[0].id, fingerprint);

    let finding_matches = store.ids_starting_with(&finding[..12]).unwrap();
    assert_eq!(finding_matches.len(), 1);
    assert_eq!(finding_matches[0].kind, IdKind::Occurrence);
    assert_eq!(finding_matches[0].id, finding);

    assert!(store.ids_starting_with("ffffffffffff").unwrap().is_empty());
    assert!(
        store.ids_starting_with("%").unwrap().is_empty(),
        "a percent is a literal prefix character, not a wildcard"
    );
    assert!(
        store.ids_starting_with("_").unwrap().is_empty(),
        "an underscore is a literal prefix character, not a wildcard"
    );
}

#[test]
fn a_structural_group_persists_its_similarity_breakdown() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].clone_type = CloneClass::Type2;
    snapshot.groups[0].similarity = Some(SimilarityBreakdownRow {
        weight_version: "structural-verify-v1".to_string(),
        lexical: 0.8,
        structural: 0.95,
        control_flow: Some(0.9),
        // Structural mode resolves no types.
        type_similarity: None,
        api: Some(0.5),
        composite: 0.87,
        min_pairwise: 0.72,
        confidence_band: Confidence::Medium,
    });
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let breakdown = groups[0]
        .similarity
        .as_ref()
        .expect("the structural group carries a breakdown");
    assert_eq!(breakdown.weight_version, "structural-verify-v1");
    assert!((breakdown.structural - 0.95).abs() < 1e-9);
    assert!((breakdown.composite - 0.87).abs() < 1e-9);
    assert!((breakdown.min_pairwise - 0.72).abs() < 1e-9);
    // The unmeasured type dimension survives the round-trip as absent.
    assert!(breakdown.type_similarity.is_none());
    assert_eq!(breakdown.api, Some(0.5));
    // The band is not derivable from the numbers, so it is stored alongside
    // them rather than recomputed on read.
    assert_eq!(breakdown.confidence_band.as_deref(), Some("medium"));

    // The same evidence is reachable from a single occurrence, which is what
    // `explain` looks up.
    let finding_hex = groups[0].members[0].finding_hex.clone();
    let occurrence = store
        .occurrence(&finding_hex)
        .unwrap()
        .expect("the occurrence is stored");
    assert_eq!(occurrence.clone_type, "type-2");
    assert_eq!(
        occurrence.member_count,
        i64::try_from(groups[0].members.len()).unwrap()
    );
    let breakdown = occurrence
        .similarity
        .expect("the occurrence carries its group's breakdown");
    assert!((breakdown.composite - 0.87).abs() < 1e-9);
    assert_eq!(breakdown.confidence_band.as_deref(), Some("medium"));
}

#[test]
fn unmeasured_similarity_dimensions_round_trip_as_absent() {
    // Empty CFG and API evidence carry no pairwise agreement. The nullable
    // columns must preserve that distinction instead of inventing 1.0 values.
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.groups[0].similarity = Some(SimilarityBreakdownRow {
        weight_version: "structural-verify-v1".to_string(),
        lexical: 1.0,
        structural: 1.0,
        control_flow: None,
        type_similarity: None,
        api: None,
        composite: 1.0,
        min_pairwise: 1.0,
        confidence_band: Confidence::High,
    });
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let breakdown = groups[0]
        .similarity
        .as_ref()
        .expect("the group carries a breakdown");
    assert!(breakdown.api.is_none());
    assert!(breakdown.control_flow.is_none());
    assert!((breakdown.composite - 1.0).abs() < 1e-9);
}

#[test]
fn a_suppressed_occurrence_explains_the_rule_that_hid_it() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
    let detectors = detector_versions();
    let mut store = Store::open_in_memory().unwrap();

    let mut snapshot = sample_snapshot(&variant, &detectors);
    snapshot.suppressions = vec![SuppressionRuleRow {
        scope: "symbol_pattern".to_string(),
        pattern: "checksum_*".to_string(),
        reason: Some("generated checksum helpers".to_string()),
    }];
    snapshot.groups[0].suppressed_by = Some(0);
    snapshot.groups[0].boilerplate = Some(Boilerplate::Forwarding);
    let run_id = store.record_snapshot(&snapshot).unwrap();

    let groups = store.run_groups(run_id).unwrap();
    let occurrence = store
        .occurrence(&groups[0].members[0].finding_hex)
        .unwrap()
        .expect("a suppressed occurrence is still stored");
    let rule = occurrence
        .suppression
        .expect("the occurrence names the rule that hid it");
    assert_eq!(rule.scope, "symbol_pattern");
    assert_eq!(rule.pattern, "checksum_*");
    assert_eq!(rule.reason.as_deref(), Some("generated checksum helpers"));
    assert_eq!(rule.active, Some(true));
    assert_eq!(occurrence.boilerplate.as_deref(), Some("forwarding"));
}

#[test]
fn a_boilerplate_group_records_what_it_is_independently_of_policy() {
    let variant = BuildVariant::structural(LanguageSelection::default(), Language::C);
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
    let variant = BuildVariant::fast(LanguageSelection::default(), Language::C);
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
