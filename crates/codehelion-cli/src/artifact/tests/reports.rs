use super::*;

/// A format is one word, on the command line and in the report alike.
///
/// The assertion a caller writes and the label they then read back have to
/// be the same string, or the report cannot be checked against the request
/// that produced it.
#[test]
fn a_format_is_named_the_same_way_on_the_command_line_and_in_a_report() {
    use clap::ValueEnum as _;

    for format in ArtifactInputFormat::value_variants() {
        let spelling = format
            .to_possible_value()
            .expect("every input format is selectable");
        assert_eq!(spelling.get_name(), input_format(*format).name());
    }
}

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
fn artifact_output_preserves_existing_files_until_forced() {
    let directory = tempfile::tempdir().expect("temporary output directory");
    let path = directory.path().join("report.txt");
    fs::write(&path, b"old report").expect("seed existing output");

    let error = write_output(&path, b"new report", false).expect_err("overwrite is refused");
    assert!(error.to_string().contains("pass --force"));
    assert_eq!(fs::read(&path).unwrap(), b"old report");

    write_output(&path, b"new report", true).expect("forced overwrite succeeds");
    assert_eq!(fs::read(&path).unwrap(), b"new report");
}

#[test]
fn artifact_container_facts_reach_json_text_and_csv_without_raw_data() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.architecture = Some("aarch64".to_owned());
    artifact.skipped_architectures = vec!["x86_64".to_owned()];
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
        ArtifactReport::from_ir(std::path::Path::new("fixture.elf"), &artifact, None, None)
            .with_containment(Some(ArtifactContainment {
                max_input_bytes: 1024,
                worker_timeout_seconds: 10,
                worker_memory_limit_bytes: 4096,
            }));

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["section_details"][0]["size"], 32);
    assert_eq!(json["import_details"][0]["name"], "puts");
    assert_eq!(json["relocation_details"][0]["target"], "puts");
    assert_eq!(json["data_segment_details"][0]["size"], 16);
    assert_eq!(json["architecture"], "aarch64");
    assert_eq!(json["skipped_architectures"], serde_json::json!(["x86_64"]));
    assert_eq!(json["containment"]["worker_memory_limit_bytes"], 4096);
    assert!(json["data_segment_details"][0].get("bytes").is_none());

    let mut text = Vec::new();
    render_text(&report, true, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains(".text: offset 16, 32 bytes (executable)"));
    assert!(text.contains("import function libc::puts"));
    assert!(text.contains("relocation Relative section 1 offset 24 target puts"));
    assert!(text.contains("section 2 offset 64 size 16"));
    assert!(text.contains("architecture: aarch64"));
    assert!(text.contains("skipped architectures: x86_64"));
    assert!(text.contains(
        "untrusted containment: input 1024 bytes, worker timeout 10s, worker memory 4096 bytes"
    ));

    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(
        csv.lines()
            .next()
            .unwrap()
            .ends_with("section,executable,module,duplicated_bytes_normalized")
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
        br#"{"version":3,"sources":["src/lib.rs"],"names":[],"mappings":"YAIA"}"#,
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
        source_map_locations(&maps),
        vec![SourceMapLocation {
            generated_offset: 12,
            source_url: "src/lib.rs".to_owned(),
            source_line: Some(5),
        }]
    );
    assert_eq!(
        maps[1].status,
        SourceMapResolutionStatus::Unavailable {
            reason: "non_local_reference"
        }
    );
}

#[test]
fn text_report_says_when_normalized_duplicates_are_unavailable() {
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None);
    let mut text = Vec::new();

    render_text(&report, false, &mut text).unwrap();

    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("normalized unavailable (no normalizer for this architecture)"));
    // The size categories say the same thing in the same words rather than
    // printing a zero that reads as "none found".
    assert!(
        text.contains("duplicated_bytes_normalized: unavailable"),
        "{text}"
    );
}

/// One symbol that differs from its neighbours only in the bytes a normalizer
/// rewrites away.
fn normalizable_symbol(
    offset: u64,
    code: &[u8],
    normalized: &[u8],
) -> codehelion_artifact::ArtifactSymbol {
    codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "symbol",
            &offset.to_le_bytes(),
        ),
        name: None,
        exported: false,
        section: Some(1),
        offset,
        size: code.len() as u64,
        size_inferred: false,
        code: code.to_vec(),
        normalized: Some(codehelion_artifact::NormalizedInstructions {
            version: "test-normal-v1".to_owned(),
            bytes: normalized.to_vec(),
        }),
        inline_stack: Vec::new(),
    }
}

/// The size categories report the same normalized total the duplicate listing
/// does, each naming the evidence behind it.
///
/// The two blocks are read by different readers — one came for the groups, one
/// came for the size — and only one of them saw the larger number.
#[test]
fn size_categories_report_the_same_normalized_total_the_duplicate_listing_does() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.capabilities.normalized_duplicates = true;
    artifact.observed_bytes = 100;
    artifact.symbols = vec![
        normalizable_symbol(10, &[1, 2], &[9]),
        normalizable_symbol(20, &[1, 3], &[9]),
        normalizable_symbol(30, &[1, 4], &[9]),
    ];
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let mut text = Vec::new();

    render_text(&report, false, &mut text).unwrap();

    let text = String::from_utf8(text).unwrap();
    let normalized = report.duplicates.normalized_duplicated_bytes;
    assert!(normalized > 0, "the fixture normalizes to one group");
    assert_eq!(report.sizes.duplicated_bytes_normalized, Some(normalized));
    assert!(
        text.contains(&format!(
            "duplicated_bytes_normalized: {normalized} (weaker evidence: equal after normalization)"
        )),
        "{text}"
    );
    assert!(
        text.contains("duplicated_bytes: 0 (byte-identical groups only)"),
        "{text}"
    );
    // The observation stays out of the bound that claims to be one.
    assert_eq!(report.sizes.upper_bound_savings_bytes, Some(0));
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
        duplicated_bytes_normalized: Some(90),
        retained_bytes: Some(60),
        shared_dependency_bytes: Some(40),
        duplicated_data_bytes: Some(30),
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
        // Normalized duplication stands beside byte-identical duplication and
        // is added into neither it nor any savings value: it is reached
        // through a rewriting rule, not observed directly.
        ("duplicated_bytes_normalized", 90),
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
        ("duplicated_bytes_normalized", "90"),
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

/// One symbol whose identity follows its seed, so a fixture can decide on its
/// own which changed symbols carry a name.
fn comparison_symbol(
    name: Option<&str>,
    seed: &[u8],
    size: u64,
) -> codehelion_artifact::ArtifactSymbol {
    codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", seed),
        name: name.map(ToOwned::to_owned),
        exported: false,
        section: None,
        offset: 0,
        size,
        size_inferred: false,
        code: vec![1; usize::try_from(size).unwrap()],
        normalized: None,
        inline_stack: Vec::new(),
    }
}

/// A comparison of two artifacts holding the given symbols.
fn symbol_comparison(
    before_symbols: Vec<codehelion_artifact::ArtifactSymbol>,
    after_symbols: Vec<codehelion_artifact::ArtifactSymbol>,
) -> ArtifactComparisonReport {
    let mut before = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    before.symbols = before_symbols;
    before.observed_bytes = 64;
    let mut after = before.clone();
    after.symbols = after_symbols;
    after.observed_bytes = 32;
    ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &before,
        None,
        std::path::Path::new("after.wasm"),
        &after,
        None,
    )
}

#[test]
fn comparison_text_folds_every_symbol_change_that_carries_no_name() {
    let report = symbol_comparison(
        vec![
            comparison_symbol(None, b"first", 4),
            comparison_symbol(None, b"second", 8),
        ],
        Vec::new(),
    );
    assert_eq!(report.symbol_deltas.len(), 2);

    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("note: 2 of 2 listed symbol changes have no name"),
        "{text}"
    );
    assert!(text.contains("cannot be paired"), "{text}");
    assert!(text.contains("keep their symbol names"), "{text}");
    assert!(!text.contains("<unnamed>"), "{text}");
    assert_eq!(
        text.lines()
            .filter(|line| line.contains("listed symbol changes have no name"))
            .count(),
        1,
        "{text}"
    );
}

#[test]
fn comparison_text_lists_named_symbol_changes_and_folds_only_the_rest() {
    let report = symbol_comparison(
        vec![
            comparison_symbol(Some("named_symbol"), b"first", 4),
            comparison_symbol(None, b"second", 8),
            comparison_symbol(None, b"third", 16),
        ],
        Vec::new(),
    );
    assert_eq!(report.symbol_deltas.len(), 3);

    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("removed named_symbol"), "{text}");
    assert!(
        text.contains("note: 2 of 3 listed symbol changes have no name"),
        "{text}"
    );
    assert!(!text.contains("<unnamed>"), "{text}");
}

#[test]
fn comparison_json_keeps_the_symbol_changes_the_text_folded() {
    let report = symbol_comparison(
        vec![
            comparison_symbol(Some("named_symbol"), b"first", 4),
            comparison_symbol(None, b"second", 8),
            comparison_symbol(None, b"third", 16),
        ],
        Vec::new(),
    );
    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("listed symbol changes have no name")
    );

    let json = serde_json::to_value(&report).unwrap();
    let deltas = json["symbol_deltas"].as_array().unwrap();
    assert_eq!(deltas.len(), 3);
    assert_eq!(
        deltas
            .iter()
            .filter(|delta| delta["name"].is_null())
            .count(),
        2
    );
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-comparison-report-v1.schema.json",
        ARTIFACT_COMPARISON_REPORT_JSON_SCHEMA,
        &json,
    );

    let mut csv = Vec::new();
    render_compare_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert_eq!(
        csv.lines()
            .filter(|row| row.starts_with("symbol-delta,"))
            .count(),
        3,
        "{csv}"
    );
}

#[test]
fn comparison_text_states_which_direction_each_byte_difference_moved() {
    let report = symbol_comparison(vec![comparison_symbol(None, b"only", 4)], Vec::new());
    assert_eq!(
        report.observed_size_reduction_bytes,
        ObservedSizeReductionBytes(32)
    );

    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("observed size: -32 bytes (smaller)"),
        "{text}"
    );
    assert!(
        text.contains("duplicated code: +0 bytes (no change)"),
        "{text}"
    );
    for line in text.lines() {
        assert!(
            !(line.starts_with("observed_size_reduction_bytes")
                || line.starts_with("duplicated_code_delta_bytes")),
            "{text}"
        );
    }
}

#[test]
fn comparison_text_reads_a_grown_artifact_as_larger() {
    let mut report = symbol_comparison(Vec::new(), Vec::new());
    report.observed_size_reduction_bytes = ObservedSizeReductionBytes(-16);
    report.duplicated_code_delta_bytes = 24;
    report.duplicated_data_delta_bytes = Some(-8);

    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("observed size: +16 bytes (larger)"), "{text}");
    assert!(
        text.contains("duplicated code: +24 bytes (more duplicated)"),
        "{text}"
    );
    assert!(
        text.contains("duplicated data: -8 bytes (less duplicated)"),
        "{text}"
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
fn comparison_warns_when_neither_build_variant_is_supplied() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let report = ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &artifact,
        None,
        std::path::Path::new("after.wasm"),
        &artifact,
        None,
    );
    assert_eq!(
        report.build_variant_warning.as_deref(),
        Some("no build variants were supplied; build-condition differences cannot be assessed")
    );
    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("build variant warning: no build variants were supplied")
    );
    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json["build_variant_warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("no build variants"))
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
    let error = inspect(file.path(), 8, None, None, None).unwrap_err();
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
    assert_eq!(
        csv("=HYPERLINK(\"https://example.invalid\")"),
        "\"'=HYPERLINK(\"\"https://example.invalid\"\")\""
    );
    assert_eq!(csv("+SUM(1,2)"), "\"'+SUM(1,2)\"");
    assert_eq!(csv("-1+2"), "'-1+2");
    assert_eq!(csv("@command"), "'@command");
    assert_eq!(csv("\tformula"), "'\tformula");
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
    let error = parse_input_format(
        b"\0asm\x01\0\0\0",
        Some(ArtifactInputFormat::Elf),
        None,
        None,
    )
    .unwrap_err();
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
        arch: None,
        before_build_variant: None,
        after_build_variant: None,
        format: ArtifactFormat::Text,
        output: None,
        force: false,
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

/// A comparison request carrying only the calibration selectors under test.
fn calibration_request(
    source_run: Option<i64>,
    clone_group: Option<&str>,
    db: Option<&std::path::Path>,
) -> ArtifactCompareArgs {
    ArtifactCompareArgs {
        before: std::path::PathBuf::from("before.wasm"),
        after: std::path::PathBuf::from("after.wasm"),
        input_format: None,
        arch: None,
        before_build_variant: None,
        after_build_variant: None,
        format: ArtifactFormat::Text,
        output: None,
        force: false,
        max_bytes: DEFAULT_ARTIFACT_MAX_BYTES,
        timeout_seconds: DEFAULT_ARTIFACT_TIMEOUT_SECONDS,
        max_memory_bytes: None,
        untrusted: false,
        source_run,
        clone_group: clone_group.map(ToOwned::to_owned),
        db: db.map(ToOwned::to_owned),
    }
}

#[test]
fn a_database_without_a_calibration_request_is_refused_by_naming_the_database() {
    let error = calibration_database(&calibration_request(
        None,
        None,
        Some(std::path::Path::new("audit.db")),
    ))
    .expect_err("a database alone selects no calibration");
    assert_eq!(
        error.to_string(),
        "--db was given without --source-run and --clone-group; artifact compare uses --db only to record a calibration"
    );
}

#[test]
fn a_source_run_without_a_clone_group_is_refused_by_naming_the_missing_group() {
    let error = calibration_database(&calibration_request(Some(7), None, None))
        .expect_err("a source run alone selects no clone group");
    assert_eq!(
        error.to_string(),
        "--source-run was given without --clone-group; artifact compare records a calibration for one clone group of that run"
    );
}

#[test]
fn a_clone_group_without_a_source_run_is_refused_by_naming_the_missing_run() {
    let error = calibration_database(&calibration_request(None, Some("deadbeef"), None))
        .expect_err("a clone group alone selects no source run");
    assert_eq!(
        error.to_string(),
        "--clone-group was given without --source-run; artifact compare records a calibration for that group in one scan run"
    );
}

#[test]
fn a_calibration_request_without_a_database_flag_resolves_the_configured_default() {
    let resolved = calibration_database(&calibration_request(Some(7), Some("deadbeef"), None))
        .expect("the default database resolves")
        .expect("a calibration request selects a database");
    assert_eq!(
        resolved,
        crate::resolve_db(crate::scan::DatabaseUse::Recording, None)
            .expect("the configured default database")
    );
}

#[test]
fn an_explicit_calibration_database_is_used_as_given() {
    let requested = std::path::Path::new("audit.db");
    let resolved = calibration_database(&calibration_request(
        Some(7),
        Some("deadbeef"),
        Some(requested),
    ))
    .expect("an explicit database resolves")
    .expect("a calibration request selects a database");
    assert_eq!(resolved, requested);
}

#[test]
fn a_comparison_without_calibration_selectors_opens_no_database() {
    assert!(
        calibration_database(&calibration_request(None, None, None))
            .expect("a plain comparison resolves no database")
            .is_none()
    );
}

#[test]
fn debug_companion_is_rejected_for_wasm() {
    let error = parse_input_format(b"\0asm\x01\0\0\0", None, Some(b"debug"), None).unwrap_err();
    assert!(error.to_string().contains("only supported for ELF"));
}

#[test]
fn architecture_selection_is_rejected_for_non_macho_inputs() {
    let error = parse_input_format(b"\0asm\x01\0\0\0", None, None, Some("wasm32")).unwrap_err();
    assert!(error.to_string().contains("only supported for Mach-O"));
}

#[test]
fn empty_archive_input_is_parsed_without_treating_it_as_unknown() {
    let archive = parse_input_format(b"!<arch>\n", None, None, None).expect("parse archive");
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
