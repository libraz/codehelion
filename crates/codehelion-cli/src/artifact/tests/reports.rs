use super::*;

#[test]
fn wasm_report_is_versioned_and_does_not_expose_code_bytes() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains(ARTIFACT_REPORT_SCHEMA_VERSION));
    assert!(json.contains("fixture.wasm"));
    assert!(!json.contains("\"code\": ["));
}

#[test]
fn artifact_container_facts_reach_json_text_and_csv_without_raw_data() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact
        .sections
        .push(codehelion_artifact::ArtifactSection {
            name: Some(".text".to_owned()),
            offset: 16,
            size: 32,
            executable: true,
        });
    artifact.imports.push(codehelion_artifact::ArtifactImport {
        module: Some("libc".to_owned()),
        name: Some("puts".to_owned()),
        kind: codehelion_artifact::ArtifactImportKind::Function,
    });
    artifact
        .relocations
        .push(codehelion_artifact::ArtifactRelocation {
            section: Some(1),
            offset: 24,
            kind: "Relative".to_owned(),
            target: Some("puts".to_owned()),
        });
    artifact
        .data_segments
        .push(codehelion_artifact::ArtifactDataSegment {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "data",
                b"0123456789abcdef",
            ),
            section: Some(2),
            offset: 64,
            bytes: b"0123456789abcdef".to_vec(),
        });
    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.elf"), &artifact, None, None);

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["section_details"][0]["size"], 32);
    assert_eq!(json["import_details"][0]["name"], "puts");
    assert_eq!(json["relocation_details"][0]["target"], "puts");
    assert_eq!(json["data_segment_details"][0]["size"], 16);
    assert!(json["data_segment_details"][0].get("bytes").is_none());

    let mut text = Vec::new();
    render_text(&report, true, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains(".text: offset 16, 32 bytes (executable)"));
    assert!(text.contains("import function libc::puts"));
    assert!(text.contains("relocation Relative section 1 offset 24 target puts"));
    assert!(text.contains("section 2 offset 64 size 16"));

    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(
        csv.lines()
            .next()
            .unwrap()
            .ends_with("section,executable,module")
    );
    for record_type in ["section", "import", "relocation", "data-segment"] {
        assert!(
            csv.lines()
                .any(|line| line.starts_with(&format!("{record_type},"))),
            "missing {record_type} CSV row"
        );
    }
}

#[test]
fn artifact_and_calibration_json_reports_validate_against_shipped_schemas() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let artifact_report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-report-v1.schema.json",
        ARTIFACT_REPORT_JSON_SCHEMA,
        &serde_json::to_value(artifact_report).unwrap(),
    );
    let calibration_report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run: 1,
        statistics: artifact_savings_calibration_statistics(&[]),
        strata: Vec::new(),
        comparison: None,
    };
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-calibration-report-v1.schema.json",
        ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA,
        &serde_json::to_value(calibration_report).unwrap(),
    );
}

#[test]
fn wasm_source_maps_are_read_only_from_the_artifact_directory() {
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("module.wasm");
    fs::write(&artifact_path, b"\0asm\x01\0\0\0").unwrap();
    fs::write(
        directory.path().join("module.wasm.map"),
        br#"{"version":3,"sources":["src/lib.rs"],"names":[],"mappings":""}"#,
    )
    .unwrap();
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact
        .source_mappings
        .push(codehelion_artifact::ArtifactSourceMapping {
            uri: "module.wasm.map".to_owned(),
        });
    artifact
        .source_mappings
        .push(codehelion_artifact::ArtifactSourceMapping {
            uri: "https://example.invalid/module.wasm.map".to_owned(),
        });

    let maps = resolve_wasm_source_maps(&artifact_path, &artifact, 1024);

    assert_eq!(maps.len(), 2);
    assert!(matches!(
        &maps[0].status,
        SourceMapResolutionStatus::Resolved { sources, .. }
            if sources == &["src/lib.rs".to_owned()]
    ));
    assert_eq!(
        maps[1].status,
        SourceMapResolutionStatus::Unavailable {
            reason: "non_local_reference"
        }
    );
}

#[test]
fn wasm_source_map_must_be_a_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    let artifact_path = directory.path().join("module.wasm");
    fs::write(&artifact_path, b"\0asm\x01\0\0\0").unwrap();
    fs::create_dir(directory.path().join("module.wasm.map")).unwrap();

    let map = resolve_wasm_source_map(&artifact_path, "module.wasm.map", 1024);

    assert_eq!(
        map.status,
        SourceMapResolutionStatus::Unavailable {
            reason: "map_not_readable"
        }
    );
}

#[test]
fn text_report_calls_duplicate_bytes_observed_not_savings() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    for category in [
        "observed_bytes",
        "duplicated_bytes",
        "retained_bytes",
        "shared_dependency_bytes",
        "duplicated_data_bytes",
        "upper_bound_savings_bytes",
        "estimated_refactor_savings_bytes",
        "verified_savings_bytes",
    ] {
        assert!(
            text.contains(category),
            "missing {category} from text report"
        );
    }
    assert!(text.contains("observed duplicate bytes"));
    assert!(text.contains("upper bound, not guaranteed"));
    assert!(text.contains("estimated_refactor_savings_bytes: unavailable"));
    assert!(text.contains("clone_confidence: High"));
    assert!(text.contains("savings_confidence: Unavailable"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], ARTIFACT_REPORT_SCHEMA_VERSION);
    for category in [
        "observed_bytes",
        "duplicated_bytes",
        "retained_bytes",
        "shared_dependency_bytes",
        "duplicated_data_bytes",
        "upper_bound_savings_bytes",
        "estimated_refactor_savings_bytes",
        "verified_savings_bytes",
        "clone_confidence",
        "savings_confidence",
        "assumptions",
    ] {
        assert!(
            json["sizes"].get(category).is_some(),
            "missing {category} from JSON report"
        );
    }

    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut lines = csv.lines();
    let header: Vec<_> = lines.next().unwrap().split(',').collect();
    let summary: Vec<_> = lines.next().unwrap().split(',').collect();
    assert_eq!(header.len(), summary.len());
    for (field, expected) in [
        ("observed_bytes", "8"),
        ("duplicated_bytes", "0"),
        ("upper_bound_savings_bytes", "0"),
        ("estimated_refactor_savings_bytes", "unavailable"),
        ("verified_savings_bytes", "unavailable"),
    ] {
        let index = header.iter().position(|value| *value == field).unwrap();
        assert_eq!(summary[index], expected, "unexpected {field} value");
    }
}

#[test]
fn savings_categories_remain_distinct_in_every_artifact_report_format() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let mut report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    report.sizes = metrics::SizeClassification {
        observed_bytes: 100,
        duplicated_bytes: 80,
        retained_bytes: Some(60),
        shared_dependency_bytes: Some(40),
        duplicated_data_bytes: 30,
        upper_bound_savings_bytes: Some(20),
        estimated_refactor_savings_bytes: Some(EstimatedRefactorSavingsBytes(10)),
        verified_savings_bytes: Some(VerifiedSavingsBytes(5)),
        clone_confidence: EvidenceConfidence::High,
        savings_confidence: EvidenceConfidence::Low,
        assumptions: Vec::new(),
    };
    let json = serde_json::to_value(&report).unwrap();
    for (field, expected) in [
        ("observed_bytes", 100),
        ("duplicated_bytes", 80),
        ("retained_bytes", 60),
        ("shared_dependency_bytes", 40),
        ("duplicated_data_bytes", 30),
        ("upper_bound_savings_bytes", 20),
        ("estimated_refactor_savings_bytes", 10),
        ("verified_savings_bytes", 5),
    ] {
        assert_eq!(json["sizes"][field], expected, "unexpected {field}");
    }
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut rows = csv.lines();
    let header: Vec<_> = rows.next().unwrap().split(',').collect();
    let summary: Vec<_> = rows.next().unwrap().split(',').collect();
    for (field, expected) in [
        ("observed_bytes", "100"),
        ("duplicated_bytes", "80"),
        ("retained_bytes", "60"),
        ("upper_bound_savings_bytes", "20"),
        ("estimated_refactor_savings_bytes", "10"),
        ("verified_savings_bytes", "5"),
    ] {
        let index = header.iter().position(|value| *value == field).unwrap();
        assert_eq!(summary[index], expected, "unexpected {field}");
    }
}

#[test]
fn artifact_report_exposes_build_variant_evidence_in_every_format() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let report = ArtifactReport::from_ir(
        std::path::Path::new("fixture.wasm"),
        &artifact,
        None,
        Some(ComparisonBuildVariant {
            manifest_path: "build-variant.json".to_owned(),
            fingerprint: "variant-fingerprint".to_owned(),
        }),
    );
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("build-variant.json"));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("build variant: build-variant.json")
    );
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    assert!(String::from_utf8(csv).unwrap().contains("build-variant,"));
}

#[test]
fn comparison_uses_fingerprint_for_additions_and_names_for_modifications() {
    let mut before = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    before.symbols = vec![codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("test", b"before"),
        name: Some("same_name".to_owned()),
        exported: false,
        section: None,
        offset: 0,
        size: 1,
        size_inferred: false,
        code: vec![1],
        normalized: None,
        inline_stack: Vec::new(),
    }];
    let mut after = before.clone();
    after.observed_bytes = 7;
    after.symbols[0].fingerprint =
        codehelion_artifact::ArtifactFingerprint::from_content("test", b"after");
    let mut report = ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &before,
        None,
        std::path::Path::new("after.wasm"),
        &after,
        None,
    );
    assert_eq!(report.symbol_changes.added, 1);
    assert_eq!(report.symbol_changes.removed, 1);
    assert_eq!(report.symbol_changes.modified_named_symbols, 1);
    assert_eq!(
        report.observed_size_reduction_bytes,
        ObservedSizeReductionBytes(1)
    );
    assert_eq!(report.symbol_deltas.len(), 2);
    assert!(report.duplicate_group_deltas.is_empty());
    assert!(
        report
            .symbol_deltas
            .iter()
            .any(|delta| delta.kind == "added" && delta.size_delta_bytes == 1)
    );
    assert!(
        report
            .symbol_deltas
            .iter()
            .any(|delta| delta.kind == "removed" && delta.size_delta_bytes == -1)
    );
    report.calibration = Some(CalibrationReport {
        source_run: 7,
        clone_group_fingerprint: "ab".repeat(16),
        estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes(-2),
        verified_savings_bytes: VerifiedSavingsBytes(1),
        absolute_error_bytes: 3,
        relative_error: Some(3.0),
    });
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["calibration"]["absolute_error_bytes"], 3);
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-comparison-report-v1.schema.json",
        ARTIFACT_COMPARISON_REPORT_JSON_SCHEMA,
        &json,
    );
    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("calibration: scan 7")
    );
    assert_comparison_csv_has_fixed_records(&report);
}

#[test]
fn comparison_reports_individual_duplicate_group_changes() {
    let mut before = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    before.symbols = [10_u64, 20]
        .into_iter()
        .map(|offset| codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                &offset.to_le_bytes(),
            ),
            name: None,
            exported: false,
            section: None,
            offset,
            size: 2,
            size_inferred: false,
            code: vec![1, 2],
            normalized: None,
            inline_stack: Vec::new(),
        })
        .collect();
    let mut after = before.clone();
    after.symbols.pop();
    let report = ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &before,
        None,
        std::path::Path::new("after.wasm"),
        &after,
        None,
    );
    assert!(report.duplicate_group_deltas.iter().any(|delta| {
        delta.kind == "exact" && delta.duplicated_bytes_delta == -2 && delta.members_delta == -2
    }));
    let mut csv = Vec::new();
    render_compare_csv(&report, &mut csv).unwrap();
    assert!(
        String::from_utf8(csv)
            .unwrap()
            .contains("duplicate-group-delta,")
    );
}

#[test]
fn comparison_warns_when_build_variant_evidence_differs() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let report = ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &artifact,
        Some(ComparisonBuildVariant {
            manifest_path: "debug.json".to_owned(),
            fingerprint: "before".to_owned(),
        }),
        std::path::Path::new("after.wasm"),
        &artifact,
        Some(ComparisonBuildVariant {
            manifest_path: "release.json".to_owned(),
            fingerprint: "after".to_owned(),
        }),
    );
    assert_eq!(
        report.build_variant_warning.as_deref(),
        Some("build variants differ; size and symbol changes may reflect build-condition changes")
    );
    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("build variant warning: build variants differ")
    );
    let mut csv = Vec::new();
    render_compare_csv(&report, &mut csv).unwrap();
    assert!(
        String::from_utf8(csv)
            .unwrap()
            .contains("build-variant-warning")
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["before"]["build_variant"]["manifest_path"],
        "debug.json"
    );
}

#[test]
fn build_variant_input_must_be_valid_json() {
    let manifest = tempfile::NamedTempFile::new().unwrap();
    fs::write(manifest.path(), b"not JSON").unwrap();
    let error = read_build_variant(Some(manifest.path())).unwrap_err();
    assert!(error.to_string().contains("as JSON"));
}

#[test]
fn build_variant_fingerprint_normalizes_json_whitespace_and_member_order() {
    let first = tempfile::NamedTempFile::new().unwrap();
    let second = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        first.path(),
        br#"{"profile":"release","features":["fast",true]}"#,
    )
    .unwrap();
    fs::write(
        second.path(),
        br#"{
            "features": ["fast", true],
            "profile": "release"
        }"#,
    )
    .unwrap();

    let first = read_build_variant(Some(first.path())).unwrap().unwrap();
    let second = read_build_variant(Some(second.path())).unwrap().unwrap();
    assert_ne!(first.manifest_path, second.manifest_path);
    assert_eq!(first.fingerprint, second.fingerprint);
}

#[test]
fn report_keeps_duplicate_group_members_without_emitting_code() {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.symbols = [10_u64, 20]
        .into_iter()
        .map(|offset| codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                &offset.to_le_bytes(),
            ),
            name: None,
            exported: false,
            section: None,
            offset,
            size: 2,
            size_inferred: false,
            code: vec![1, 2],
            normalized: None,
            inline_stack: Vec::new(),
        })
        .collect();
    artifact.symbols[0].exported = true;
    artifact.capabilities.call_graph = true;
    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    assert_eq!(report.duplicate_groups.exact.len(), 1);
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("exact duplicate groups:"));
    assert!(text.contains("offset 10 size 2"));
    assert!(text.contains("dead code definitive: 1 symbols"));
    assert!(!text.contains("[1, 2]"));
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("duplicate-group,fixture.wasm,wasm,exact,"));
    assert!(csv.contains("duplicate-member,fixture.wasm,wasm,exact,"));
    assert!(csv.contains("dead-code,fixture.wasm,wasm,"));
    let mut rows = csv.lines();
    let columns = rows.next().unwrap().split(',').count();
    let widths: Vec<_> = rows.map(|row| row.split(',').count()).collect();
    assert_eq!(widths, vec![columns; widths.len()]);
}

#[test]
fn input_limit_is_checked_before_reading_or_parsing() {
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), b"more than eight bytes").unwrap();
    let error = inspect(file.path(), 8, None, None).unwrap_err();
    assert!(error.to_string().contains("configured maximum of 8 bytes"));
}

#[test]
fn artifact_ir_serialization_stops_at_its_storage_ceiling() {
    let mut output = CappedArtifactIrBuffer::new(3);
    assert_eq!(output.write(b"abc").expect("write within ceiling"), 3);
    assert!(output.write(b"d").is_err());
    assert!(output.exceeded);
    assert_eq!(output.bytes, b"abc");
}

#[test]
fn artifact_input_must_be_a_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    let error = read_artifact_input(directory.path(), 8, "artifact").unwrap_err();
    assert!(error.to_string().contains("is not a regular file"));
}

#[test]
fn csv_quotes_delimiters_and_embedded_quotes() {
    assert_eq!(csv("plain"), "plain");
    assert_eq!(csv("a,b"), "\"a,b\"");
    assert_eq!(csv("a\"b"), "\"a\"\"b\"");
}

#[test]
fn calibration_summary_keeps_absolute_and_relative_statistics_separate() {
    let report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run: 7,
        statistics: ArtifactSavingsCalibrationStatistics {
            samples: 4,
            median_absolute_error_bytes: Some(5.5),
            p90_absolute_error_bytes: Some(10),
            relative_error_samples: 3,
            median_relative_error: Some(0.8),
            p90_relative_error: Some(1.0),
        },
        strata: vec![CalibrationStratumReport {
            dimension: "artifact_format",
            key: "elf".to_owned(),
            statistics: ArtifactSavingsCalibrationStatistics {
                samples: 2,
                median_absolute_error_bytes: Some(4.0),
                p90_absolute_error_bytes: Some(7),
                relative_error_samples: 2,
                median_relative_error: Some(0.5),
                p90_relative_error: Some(0.7),
            },
        }],
        comparison: None,
    };
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["statistics"]["samples"], 4);
    assert_eq!(json["statistics"]["relative_error_samples"], 3);
    assert_eq!(json["strata"][0]["dimension"], "artifact_format");
    let mut text = Vec::new();
    render_calibration_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("absolute error: median 5.5000 bytes"));
    assert!(text.contains("artifact_format elf"));
    let mut csv = Vec::new();
    render_calibration_csv(&report, &mut csv).unwrap();
    assert!(
        String::from_utf8(csv)
            .unwrap()
            .contains("7,overall,,,,4,5.5000,10,3,0.8000,1.0000")
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the two reports and every comparison outcome remain visible together"
)]
fn calibration_comparison_reports_deltas_without_a_threshold_gate() {
    let mut report = CalibrationSummaryReport {
        schema_version: ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
        source_run: 7,
        statistics: ArtifactSavingsCalibrationStatistics {
            samples: 4,
            median_absolute_error_bytes: Some(5.5),
            p90_absolute_error_bytes: Some(10),
            relative_error_samples: 3,
            median_relative_error: Some(0.8),
            p90_relative_error: Some(1.0),
        },
        strata: vec![CalibrationStratumReport {
            dimension: "artifact_format",
            key: "elf".to_owned(),
            statistics: ArtifactSavingsCalibrationStatistics {
                samples: 4,
                median_absolute_error_bytes: Some(5.5),
                p90_absolute_error_bytes: Some(10),
                relative_error_samples: 3,
                median_relative_error: Some(0.8),
                p90_relative_error: Some(1.0),
            },
        }],
        comparison: None,
    };
    let baseline = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        baseline.path(),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION,
            "source_run": 6,
            "statistics": {
                "samples": 2,
                "median_absolute_error_bytes": 3.0,
                "p90_absolute_error_bytes": 7,
                "relative_error_samples": 2,
                "median_relative_error": 0.5,
                "p90_relative_error": 0.7
            },
            "strata": [
                {
                    "dimension": "artifact_format",
                    "key": "elf",
                    "statistics": {
                        "samples": 2,
                        "median_absolute_error_bytes": 3.0,
                        "p90_absolute_error_bytes": 7,
                        "relative_error_samples": 2,
                        "median_relative_error": 0.5,
                        "p90_relative_error": 0.7
                    }
                },
                {
                    "dimension": "clone_type",
                    "key": "type-2",
                    "statistics": {
                        "samples": 1,
                        "median_absolute_error_bytes": 2.0,
                        "p90_absolute_error_bytes": 2,
                        "relative_error_samples": 1,
                        "median_relative_error": 0.4,
                        "p90_relative_error": 0.4
                    }
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let comparison = calibration_comparison(&report, baseline.path()).unwrap();
    assert_eq!(
        comparison.baseline_schema_version,
        ARTIFACT_CALIBRATION_REPORT_SCHEMA_VERSION
    );
    assert_eq!(comparison.baseline_source_run, 6);
    assert_eq!(comparison.overall.samples, 2);
    assert_eq!(comparison.overall.median_absolute_error_bytes, Some(2.5));
    assert_eq!(comparison.strata.len(), 2);
    assert!(comparison.strata.iter().any(|stratum| {
        stratum.dimension == "clone_type"
            && stratum.key == "type-2"
            && stratum.current.is_none()
            && stratum.delta.is_none()
    }));
    report.comparison = Some(comparison);

    let value = serde_json::to_value(&report).unwrap();
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-calibration-report-v1.schema.json",
        ARTIFACT_CALIBRATION_REPORT_JSON_SCHEMA,
        &value,
    );
    assert_eq!(value["comparison"]["overall"]["samples"], 2);
    let mut text = Vec::new();
    render_calibration_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("baseline comparison (informational; no threshold)"));
    assert!(text.contains("overall: samples +2"));
    assert!(text.contains("only one report contains this stratum"));
    let mut csv = Vec::new();
    render_calibration_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut rows = csv.lines();
    let width = rows.next().unwrap().split(',').count();
    assert!(rows.all(|row| row.split(',').count() == width));
    assert!(csv.contains("7,comparison-overall,,,6,,,,,,,2,2.5000,3,1,0.3000,0.3000"));
}

#[test]
fn input_format_is_an_assertion_on_magic_detection() {
    let error =
        parse_input_format(b"\0asm\x01\0\0\0", Some(ArtifactInputFormat::Elf), None).unwrap_err();
    assert!(error.to_string().contains("conflicts"));
}

#[test]
fn comparison_applies_the_input_format_assertion_to_both_artifacts() {
    let directory = tempfile::tempdir().expect("temporary artifact directory");
    let before = directory.path().join("before.wasm");
    let after = directory.path().join("after.wasm");
    fs::write(&before, b"\0asm\x01\0\0\0").expect("write before artifact");
    fs::write(&after, b"\0asm\x01\0\0\0").expect("write after artifact");
    let args = ArtifactCompareArgs {
        before,
        after,
        input_format: Some(ArtifactInputFormat::Elf),
        before_build_variant: None,
        after_build_variant: None,
        format: ArtifactFormat::Text,
        output: None,
        max_bytes: DEFAULT_ARTIFACT_MAX_BYTES,
        timeout_seconds: DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        max_memory_bytes: None,
        untrusted: false,
        source_run: None,
        clone_group: None,
        db: None,
    };
    let error = compare_direct(&args, &mut Vec::new()).expect_err("format mismatch");
    assert!(error.to_string().contains("conflicts"), "{error:#}");
}

#[test]
fn debug_companion_is_rejected_for_wasm() {
    let error = parse_input_format(b"\0asm\x01\0\0\0", None, Some(b"debug")).unwrap_err();
    assert!(error.to_string().contains("only supported for ELF"));
}

#[test]
fn empty_archive_input_is_parsed_without_treating_it_as_unknown() {
    let archive = parse_input_format(b"!<arch>\n", None, None).expect("parse archive");
    assert_eq!(archive.format, BinaryFormat::Archive);
    assert!(archive.archive_members.is_empty());
}

#[test]
fn archive_report_retains_member_failures_without_raw_member_bytes() {
    let mut archive = ArtifactIr::empty(BinaryFormat::Archive, b"archive");
    archive
        .archive_members
        .push(codehelion_artifact::ArtifactArchiveMember {
            name: "thin-member.o".to_owned(),
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "archive-member",
                b"member",
            ),
            offset: 32,
            size: 0,
            format: Some(BinaryFormat::Elf),
            thin: true,
            parse_error: Some("external member paths are not followed".to_owned()),
        });

    let report = ArtifactReport::from_ir(FilePath::new("fixture.a"), &archive, None, None);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["archive_members"][0]["name"], "thin-member.o");
    assert_eq!(json["archive_members"][0]["thin"], true);
    assert!(
        json["archive_members"][0]["parse_error"]
            .as_str()
            .unwrap()
            .contains("not followed")
    );
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("archive members: 0 parsed, 1 unavailable")
    );
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("archive-member,fixture.a,archive,elf"));
    assert!(csv.contains("thin-member.o"));
    assert!(csv.contains("external member paths are not followed"));
}
