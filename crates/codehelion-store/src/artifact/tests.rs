use super::*;

const ARTIFACT_IR_SCHEMA: &str = "artifact-ir-v7";

#[test]
fn persisted_confidences_display_their_sql_vocabulary() {
    assert_eq!(ArtifactAnalysisSavingsConfidence::High.to_string(), "high");
    assert_eq!(
        ArtifactAnalysisSavingsConfidence::Medium.to_string(),
        "medium"
    );
    assert_eq!(ArtifactAnalysisSavingsConfidence::Low.to_string(), "low");
    assert_eq!(
        ArtifactAnalysisSavingsConfidence::Unavailable.to_string(),
        "unavailable"
    );
    assert_eq!(
        ArtifactAnalysisMappingConfidence::Exact.to_string(),
        "exact"
    );
    assert_eq!(
        ArtifactAnalysisMappingConfidence::Strong.to_string(),
        "strong"
    );
    assert_eq!(ArtifactAnalysisMappingConfidence::Weak.to_string(), "weak");
    assert_eq!(
        ArtifactAnalysisMappingConfidence::Ambiguous.to_string(),
        "ambiguous"
    );
}

#[test]
fn calibration_statistics_keep_relative_errors_separate_from_zero_measurements() {
    let calibration = |absolute_error_bytes, relative_error| ArtifactAnalysisSavingsCalibration {
        schema_version: ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION.to_owned(),
        artifact_analysis_id: 1,
        source_scan_run_id: 2,
        clone_group_fingerprint: [3; 16],
        source_build_variant_fingerprint: [4; 16],
        before_artifact_build_variant_fingerprint: [5; 16],
        after_artifact_fingerprint: [6; 16],
        after_artifact_build_variant_fingerprint: [5; 16],
        estimated_refactor_savings_bytes: 0,
        verified_savings_bytes: 0,
        absolute_error_bytes,
        relative_error,
        recorded_at: "2026-07-30T00:00:00Z".to_owned(),
    };
    let statistics = artifact_savings_calibration_statistics(&[
        calibration(1, Some(0.1)),
        calibration(3, None),
        calibration(8, Some(0.8)),
        calibration(10, Some(1.0)),
    ]);
    assert_eq!(statistics.samples, 4);
    assert_eq!(statistics.median_absolute_error_bytes, Some(5.5));
    assert_eq!(statistics.p90_absolute_error_bytes, Some(10));
    assert_eq!(statistics.relative_error_samples, 3);
    assert_eq!(statistics.median_relative_error, Some(0.8));
    assert_eq!(statistics.p90_relative_error, Some(1.0));
    assert_eq!(
        artifact_savings_calibration_statistics(&[]),
        ArtifactSavingsCalibrationStatistics {
            samples: 0,
            median_absolute_error_bytes: None,
            p90_absolute_error_bytes: None,
            relative_error_samples: 0,
            median_relative_error: None,
            p90_relative_error: None,
        }
    );
}

#[test]
fn mapping_evidence_derives_confidence_without_forcing_a_candidate() {
    let name = MappingEvidenceFact::SymbolName {
        source_symbol: "crate::entry".to_owned(),
        artifact_symbol: "crate::entry".to_owned(),
    };
    assert_eq!(
        MappingEvidence::new(vec![name.clone()], 1, false).confidence(),
        Some(ArtifactAnalysisMappingConfidence::Weak)
    );
    assert_eq!(
        MappingEvidence::new(
            vec![
                name,
                MappingEvidenceFact::FunctionRecipe {
                    recipe_version: FUNCTION_RECIPE_VERSION.to_owned(),
                },
            ],
            1,
            false,
        )
        .confidence(),
        Some(ArtifactAnalysisMappingConfidence::Strong)
    );
    assert_eq!(
        MappingEvidence::new(
            vec![MappingEvidenceFact::Dwarf {
                source_path: "src/lib.rs".to_owned(),
            }],
            1,
            false,
        )
        .confidence(),
        Some(ArtifactAnalysisMappingConfidence::Exact)
    );
    assert_eq!(
        MappingEvidence::new(
            vec![MappingEvidenceFact::Dwarf {
                source_path: "src/lib.rs".to_owned(),
            }],
            2,
            false,
        )
        .confidence(),
        Some(ArtifactAnalysisMappingConfidence::Ambiguous)
    );
    assert_eq!(
        MappingEvidence::new(Vec::new(), 0, false).confidence(),
        None
    );
}

#[test]
fn operation_recipe_evidence_accepts_only_its_current_v1_contract() {
    let evidence = MappingEvidence::new(
        vec![MappingEvidenceFact::FunctionRecipe {
            recipe_version: FUNCTION_RECIPE_VERSION.to_owned(),
        }],
        1,
        false,
    );
    let value = serde_json::to_value(&evidence).expect("evidence serializes");
    assert_eq!(value["facts"][0]["kind"], "function_recipe");
    assert_eq!(
        evidence.confidence(),
        Some(ArtifactAnalysisMappingConfidence::Weak)
    );

    let stale = MappingEvidence::new(
        vec![MappingEvidenceFact::FunctionRecipe {
            recipe_version: "source-artifact-operation-recipe-other".to_owned(),
        }],
        1,
        false,
    );
    assert_eq!(stale.confidence(), None);
    assert!(MappingEvidence::from_json(
            r#"{"schema_version":"source-artifact-evidence-v1","facts":[{"kind":"function_fingerprint","recipe_version":"source-artifact-operation-recipe-v1"}],"candidate_count":1,"has_conflict":false}"#,
        )
        .is_err());
}

#[test]
fn generic_origin_evidence_requires_every_v1_field() {
    let result = MappingEvidence::from_json(
        r#"{"schema_version":"source-artifact-evidence-v1","facts":[{"kind":"generic_origin","instantiation_key":"crate::render<u8>"}],"candidate_count":1,"has_conflict":false}"#,
    );
    assert!(result.is_err());
    let result = MappingEvidence::from_json(
        r#"{"schema_version":"source-artifact-evidence-v1","facts":[{"kind":"generic_origin","definition":"crate::render","instantiation_key":"crate::render<u8>"}],"candidate_count":1,"has_conflict":false}"#,
    );
    assert!(result.is_err());
}

#[test]
fn artifact_ir_storage_ceiling_rejects_oversized_documents() {
    assert!(validate_artifact_ir_size(MAX_ARTIFACT_IR_JSON_BYTES).is_ok());
    let error = validate_artifact_ir_size(MAX_ARTIFACT_IR_JSON_BYTES.saturating_add(1))
        .expect_err("oversized artifact IR must be rejected");
    assert!(matches!(
        error,
        StoreError::ArtifactIrTooLarge {
            size_bytes,
            maximum_bytes: MAX_ARTIFACT_IR_JSON_BYTES,
        } if size_bytes == MAX_ARTIFACT_IR_JSON_BYTES.saturating_add(1)
    ));
}

#[test]
fn artifact_ir_storage_requires_the_row_and_document_schemas_to_agree() {
    let snapshot = ArtifactAnalysisSnapshot {
        schema_version: ARTIFACT_IR_SCHEMA,
        path: "fixture.wasm",
        format: "wasm",
        content_fingerprint: [0; 16],
        observed_bytes: 0,
        ir_json: r#"{"schema_version":"artifact-ir-v1"}"#,
        build_variant_manifest_path: None,
        build_variant_fingerprint: None,
        started_at: "2026-08-03T00:00:00Z",
        finished_at: "2026-08-03T00:00:01Z",
        symbols: &[],
        mappings: &[],
        unmapped_symbols: &[],
        unmapped_sources: &[],
        correlation: None,
        clone_group_savings: &[],
    };

    let error = validate_artifact_ir_schema(&snapshot).expect_err("schemas must agree");
    assert!(matches!(error, StoreError::InvalidArtifactIrSchema { .. }));
}

#[test]
fn a_mapping_without_evidence_is_rejected_without_persisting_the_analysis() {
    let mut store = Store::open_in_memory().unwrap();
    let mappings = [ArtifactAnalysisMapping {
        schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
        artifact_symbol_fingerprint: [2; 16],
        source_kind: ArtifactAnalysisSourceKind::Unit,
        source_fingerprint: [3; 16],
        source_instance_fingerprint: [3; 16],
        source_build_variant_fingerprint: [4; 16],
        evidence: MappingEvidence::new(Vec::new(), 0, false),
        attributed_bytes: None,
        build_variant_fingerprint: [5; 16],
    }];

    let error = store
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: ARTIFACT_IR_SCHEMA,
            path: "fixture.so",
            format: "elf",
            content_fingerprint: [1; 16],
            observed_bytes: 0,
            ir_json: r#"{"schema_version":"artifact-ir-v7"}"#,
            build_variant_manifest_path: None,
            build_variant_fingerprint: None,
            started_at: "2026-07-30T00:00:00Z",
            finished_at: "2026-07-30T00:00:01Z",
            symbols: &[],
            mappings: &mappings,
            unmapped_symbols: &[],
            unmapped_sources: &[],
            correlation: None,
            clone_group_savings: &[],
        })
        .unwrap_err();
    assert!(matches!(error, StoreError::InvalidMappingEvidence { .. }));
    let analysis_count: i64 = store
        .conn
        .query_row("SELECT COUNT(*) FROM artifact_analysis", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(analysis_count, 0);
}

#[test]
fn artifact_analyses_with_distinct_build_variants_stay_distinct() {
    let mut store = Store::open_in_memory().unwrap();
    for (content_fingerprint, build_variant_fingerprint) in [([1; 16], [2; 16]), ([3; 16], [4; 16])]
    {
        store
            .record_artifact_analysis(&ArtifactAnalysisSnapshot {
                schema_version: ARTIFACT_IR_SCHEMA,
                path: "fixture.wasm",
                format: "wasm",
                content_fingerprint,
                observed_bytes: 8,
                ir_json: r#"{"schema_version":"artifact-ir-v7"}"#,
                build_variant_manifest_path: Some("build-variant.json"),
                build_variant_fingerprint: Some(build_variant_fingerprint),
                started_at: "2026-07-30T00:00:00Z",
                finished_at: "2026-07-30T00:00:01Z",
                symbols: &[],
                mappings: &[],
                unmapped_symbols: &[],
                unmapped_sources: &[],
                correlation: None,
                clone_group_savings: &[],
            })
            .unwrap();
    }
    let variants: Vec<Vec<u8>> = store
        .conn
        .prepare(
            "SELECT build_variant_fingerprint
                 FROM artifact_analysis
                 ORDER BY build_variant_fingerprint ASC",
        )
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(variants, vec![vec![2; 16], vec![4; 16]]);
}

#[test]
fn standalone_analysis_and_symbols_commit_together() {
    let mut store = Store::open_in_memory().unwrap();
    store
        .conn
        .execute(
            "INSERT INTO build_variant
                     (variant_fingerprint, canonical, analysis_mode, normalization_version)
                 VALUES (?1, ?2, 'structural', 1)",
            ["0123456789abcdef0123456789abcdef", "fixture-variant"],
        )
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO scan_run
                     (build_variant_id, root_path, tool_version, config_hash, config_source,
                      analysis_mode, started_at, finished_at, min_clone_tokens, status)
                 VALUES (1, 'fixture', 'test', 'config', 'defaults', 'structural',
                         '2026-07-30T00:00:00Z', '2026-07-30T00:00:01Z', 20, 'completed')",
            [],
        )
        .unwrap();
    let symbols = [ArtifactAnalysisSymbol {
        fingerprint: [2; 16],
        name: Some("entry".to_owned()),
        exported: true,
        section_index: Some(1),
        offset: 4,
        size_bytes: 8,
        size_inferred: false,
        code_fingerprint: [3; 16],
        normalization_version: Some("wasm-opcode-v1".to_owned()),
        normalization_fingerprint: Some([4; 16]),
    }];
    let mappings = [ArtifactAnalysisMapping {
        schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
        artifact_symbol_fingerprint: [2; 16],
        source_kind: ArtifactAnalysisSourceKind::Fragment,
        source_fingerprint: [6; 16],
        source_instance_fingerprint: [11; 16],
        source_build_variant_fingerprint: [9; 16],
        evidence: MappingEvidence::new(
            vec![MappingEvidenceFact::Dwarf {
                source_path: "src/lib.rs".to_owned(),
            }],
            1,
            false,
        ),
        attributed_bytes: Some(8),
        build_variant_fingerprint: [5; 16],
    }];
    let unmapped_symbols = [ArtifactAnalysisUnmappedSymbol {
        artifact_symbol_fingerprint: [7; 16],
        reason: ArtifactAnalysisUnmappedReason::DebugInfoMissing,
    }];
    let unmapped_sources = [
        ArtifactAnalysisUnmappedSource {
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: [8; 16],
            source_instance_fingerprint: [8; 16],
            source_build_variant_fingerprint: [9; 16],
            reason: ArtifactAnalysisUnmappedSourceReason::InlinedAway,
        },
        ArtifactAnalysisUnmappedSource {
            source_kind: ArtifactAnalysisSourceKind::Unit,
            source_fingerprint: [10; 16],
            source_instance_fingerprint: [10; 16],
            source_build_variant_fingerprint: [9; 16],
            reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
        },
    ];
    let savings = [ArtifactAnalysisCloneGroupSavings {
        schema_version: ARTIFACT_ANALYSIS_CLONE_GROUP_SAVINGS_SCHEMA_VERSION.to_owned(),
        source_scan_run_id: 1,
        clone_group_fingerprint: [12; 16],
        source_build_variant_fingerprint: [9; 16],
        artifact_build_variant_fingerprint: [5; 16],
        duplicated_bytes: 8,
        estimated_refactor_savings_bytes: -2,
        mapping_confidence: ArtifactAnalysisSavingsConfidence::High,
        clone_confidence: 1.0,
        model_confidence: ArtifactAnalysisSavingsConfidence::Low,
        savings_confidence: ArtifactAnalysisSavingsConfidence::Low,
        model_schema_version: "refactor-savings-model-v1".to_owned(),
        assumptions_json: r#"[{"kind":"inlining_outcome_unknown"}]"#.to_owned(),
    }];
    let id = store
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: ARTIFACT_IR_SCHEMA,
            path: "fixture.wasm",
            format: "wasm",
            content_fingerprint: [1; 16],
            observed_bytes: 12,
            ir_json: r#"{"schema_version":"artifact-ir-v7"}"#,
            build_variant_manifest_path: Some("build-variant.json"),
            build_variant_fingerprint: Some([5; 16]),
            started_at: "2026-07-30T00:00:00Z",
            finished_at: "2026-07-30T00:00:01Z",
            symbols: &symbols,
            mappings: &mappings,
            unmapped_symbols: &unmapped_symbols,
            unmapped_sources: &unmapped_sources,
            correlation: Some(ArtifactAnalysisCorrelation {
                schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION,
                source_scan_run_id: 1,
                mapping_count: 1,
                artifact_symbol_count: 1,
                mapped_symbol_count: 1,
                artifact_symbol_bytes: 8,
                mapped_symbol_bytes: 8,
            }),
            clone_group_savings: &savings,
        })
        .unwrap();
    let count: i64 = store
        .conn
        .query_row(
            "SELECT COUNT(*) FROM artifact_analysis_symbol WHERE analysis_id = ?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    let ir_json: String = store
        .conn
        .query_row(
            "SELECT ir_json FROM artifact_analysis WHERE id = ?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ir_json, r#"{"schema_version":"artifact-ir-v7"}"#);
    let variant: (Option<String>, Option<Vec<u8>>) = store
        .conn
        .query_row(
            "SELECT build_variant_manifest_path, build_variant_fingerprint
                 FROM artifact_analysis WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(variant.0.as_deref(), Some("build-variant.json"));
    assert_eq!(variant.1, Some(vec![5; 16]));
    assert_eq!(
        store.artifact_analysis_identity(id).unwrap(),
        Some(crate::query::StoredArtifactAnalysisIdentity {
            analysis_id: id,
            format: "wasm".to_owned(),
            content_fingerprint: [1; 16],
            build_variant_fingerprint: Some([5; 16]),
        })
    );
    let mapping: (String, String, i64) = store
        .conn
        .query_row(
            "SELECT source_kind, mapping_confidence, attributed_bytes
                 FROM artifact_analysis_source_mapping WHERE artifact_analysis_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(mapping, ("fragment".to_owned(), "exact".to_owned(), 8));
    let unmapped: String = store
        .conn
        .query_row(
            "SELECT reason FROM artifact_analysis_unmapped_symbol
                 WHERE artifact_analysis_id = ?1",
            [id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unmapped, "debug_info_missing");
    let stored_mappings = store.artifact_mappings(id).unwrap();
    assert_eq!(stored_mappings.len(), 1);
    assert_eq!(stored_mappings[0].artifact_symbol_fingerprint, [2; 16]);
    assert_eq!(
        stored_mappings[0].source_kind,
        ArtifactAnalysisSourceKind::Fragment
    );
    assert_eq!(stored_mappings[0].source_fingerprint, [6; 16]);
    assert_eq!(stored_mappings[0].source_instance_fingerprint, [11; 16]);
    assert_eq!(stored_mappings[0].source_build_variant_fingerprint, [9; 16]);
    assert_eq!(
        stored_mappings[0].confidence,
        ArtifactAnalysisMappingConfidence::Exact
    );
    assert_eq!(
        stored_mappings[0].evidence,
        MappingEvidence::new(
            vec![MappingEvidenceFact::Dwarf {
                source_path: "src/lib.rs".to_owned(),
            }],
            1,
            false,
        )
    );
    assert_eq!(stored_mappings[0].attributed_bytes, Some(8));
    let stored_unmapped = store.artifact_unmapped_symbols(id).unwrap();
    assert_eq!(stored_unmapped.len(), 1);
    assert_eq!(stored_unmapped[0].artifact_symbol_fingerprint, [7; 16]);
    assert_eq!(
        stored_unmapped[0].reason,
        ArtifactAnalysisUnmappedReason::DebugInfoMissing
    );
    let stored_unmapped_sources = store.artifact_unmapped_sources(id).unwrap();
    assert_eq!(stored_unmapped_sources.len(), 2);
    assert_eq!(store.artifact_clone_group_savings(id).unwrap(), savings);
    // A damaged mapping for a different finding must not make `explain`
    // decode every mapping in this analysis before reaching its target.
    store
        .conn
        .execute(
            "INSERT INTO artifact_analysis_source_mapping
                     (schema_version, artifact_analysis_id, artifact_symbol_fingerprint,
                      source_kind, source_fingerprint, source_instance_fingerprint,
                      evidence_json, mapping_confidence, attributed_bytes,
                      build_variant_fingerprint, source_build_variant_fingerprint)
                 VALUES ('unsupported-mapping-schema', ?1, ?2, 'fragment', ?3, ?4,
                         'not valid mapping JSON', 'exact', NULL, ?5, ?6)",
            params![
                id,
                [13_u8; 16].as_slice(),
                [14_u8; 16].as_slice(),
                [15_u8; 16].as_slice(),
                [5_u8; 16].as_slice(),
                [9_u8; 16].as_slice(),
            ],
        )
        .unwrap();
    assert_eq!(
        store
            .artifact_fragment_mappings("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
            .unwrap(),
        stored_mappings
    );
    assert_eq!(
        store
            .clone_group_savings(1, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
            .unwrap(),
        vec![(id, savings[0].clone())]
    );
    assert_eq!(
        store
            .clone_group_type(1, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
            .unwrap(),
        None,
    );
    let calibration = ArtifactAnalysisSavingsCalibration {
        schema_version: ARTIFACT_ANALYSIS_SAVINGS_CALIBRATION_SCHEMA_VERSION.to_owned(),
        artifact_analysis_id: id,
        source_scan_run_id: 1,
        clone_group_fingerprint: [12; 16],
        source_build_variant_fingerprint: [9; 16],
        before_artifact_build_variant_fingerprint: [5; 16],
        after_artifact_fingerprint: [13; 16],
        after_artifact_build_variant_fingerprint: [5; 16],
        estimated_refactor_savings_bytes: -2,
        verified_savings_bytes: 3,
        absolute_error_bytes: 5,
        relative_error: Some(5.0 / 3.0),
        recorded_at: "2026-07-30T00:01:00Z".to_owned(),
    };
    store
        .record_artifact_savings_calibration(&calibration)
        .unwrap();
    let saved: (i64, i64, i64, f64) = store
        .conn
        .query_row(
            "SELECT estimated_refactor_savings_bytes, verified_savings_bytes,
                        absolute_error_bytes, relative_error
                 FROM artifact_analysis_savings_calibration
                 WHERE artifact_analysis_id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(saved.0, -2);
    assert_eq!(saved.1, 3);
    assert_eq!(saved.2, 5);
    assert!((saved.3 - (5.0 / 3.0)).abs() < f64::EPSILON);
    assert_eq!(
        store
            .artifact_savings_calibrations(1, "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")
            .unwrap(),
        vec![calibration.clone()]
    );
    assert_eq!(
        store.artifact_savings_calibrations_for_run(1).unwrap(),
        vec![calibration]
    );
    assert_eq!(
        store.artifact_correlation(id).unwrap(),
        Some(crate::query::StoredArtifactAnalysisCorrelation {
            schema_version: ARTIFACT_ANALYSIS_CORRELATION_SCHEMA_VERSION.to_owned(),
            source_scan_run_id: 1,
            mapping_count: 1,
            artifact_symbol_count: 1,
            mapped_symbol_count: 1,
            artifact_symbol_bytes: 8,
            mapped_symbol_bytes: 8,
        })
    );
    assert_eq!(
        stored_unmapped_sources[0].source_kind,
        ArtifactAnalysisSourceKind::Unit
    );
    assert_eq!(
        stored_unmapped_sources[0].source_instance_fingerprint,
        [8; 16]
    );
    assert_eq!(stored_unmapped_sources[0].source_fingerprint, [8; 16]);
    assert_eq!(
        stored_unmapped_sources[0].source_build_variant_fingerprint,
        [9; 16]
    );
    assert_eq!(
        stored_unmapped_sources[0].reason,
        ArtifactAnalysisUnmappedSourceReason::InlinedAway
    );
    assert_eq!(stored_unmapped_sources[1].source_fingerprint, [10; 16]);
    assert_eq!(
        stored_unmapped_sources[1].reason,
        ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence
    );
}
