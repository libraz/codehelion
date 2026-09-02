use super::*;
use crate::artifact::model::ARTIFACT_CSV_HEADER;

/// A module whose two functions carry instruction bytes, one calling the
/// other, alongside a data segment that carries bytes of its own.
///
/// A report has to withhold both, so a fixture with neither cannot show that
/// it does.
const CODE_MODULE: &[u8] = &[
    0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 3, 2, 0, 0, 7, 7, 1, 3, b'f', b'o', b'o', 0,
    0, 10, 9, 2, 4, 0, 16, 1, 11, 2, 0, 11, 11, 6, 1, 1, 3, b'a', b'b', b'c', 0, 18, 4, b'n', b'a',
    b'm', b'e', 1, 11, 2, 0, 3, b'f', b'o', b'o', 1, 3, b'b', b'a', b'r',
];

/// [`CODE_MODULE`] with a third function `mid` inserted between the two.
///
/// The insertion moves `bar` from function index 1 to index 2 and rewrites
/// the `call` immediate in `foo` accordingly, so every index in the module
/// past the insertion point differs from the one before it.
const CODE_MODULE_WITH_INSERTED_FUNCTION: &[u8] = &[
    0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0, 3, 4, 3, 0, 0, 0, 7, 7, 1, 3, b'f', b'o', b'o',
    0, 0, 10, 13, 3, 4, 0, 16, 2, 11, 3, 0, 1, 11, 2, 0, 11, 11, 6, 1, 1, 3, b'a', b'b', b'c', 0,
    23, 4, b'n', b'a', b'm', b'e', 1, 16, 3, 0, 3, b'f', b'o', b'o', 1, 3, b'm', b'i', b'd', 2, 3,
    b'b', b'a', b'r',
];

/// Fail if any object anywhere under `value` carries instruction or segment
/// bytes.
///
/// The whole tree is walked rather than the rendered text searched: a detail
/// struct that started carrying bytes would appear as a new key at a depth
/// this test does not know in advance, and a search for one spelling of one
/// field would not see it.
fn assert_no_raw_bytes(value: &serde_json::Value, path: &str) {
    match value {
        serde_json::Value::Object(members) => {
            for (key, member) in members {
                assert!(
                    !matches!(key.as_str(), "code" | "bytes"),
                    "{path}.{key} publishes raw artifact bytes"
                );
                assert_no_raw_bytes(member, &format!("{path}.{key}"));
            }
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_no_raw_bytes(item, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

#[test]
fn wasm_report_is_versioned_and_does_not_expose_code_bytes() {
    let artifact = WasmBackend.parse(CODE_MODULE).unwrap();
    assert!(
        artifact
            .symbols
            .iter()
            .any(|symbol| !symbol.code.is_empty()),
        "the fixture must carry the instruction bytes the report has to withhold"
    );
    assert!(
        artifact
            .data_segments
            .iter()
            .any(|segment| !segment.bytes.is_empty()),
        "the fixture must carry the segment bytes the report has to withhold"
    );

    let report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["schema_version"], ARTIFACT_REPORT_SCHEMA_VERSION);
    assert_eq!(json["path"], "fixture.wasm");
    assert_no_raw_bytes(&json, "report");
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
                max_debug_derived_items: 1_024,
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
    assert_eq!(csv.lines().next().unwrap(), ARTIFACT_CSV_HEADER.join(","));
    for record_type in ["section", "import", "relocation", "data-segment"] {
        assert!(
            csv.lines()
                .any(|line| line.starts_with(&format!("{record_type},"))),
            "missing {record_type} CSV row"
        );
    }
}

/// One correlation carrying every reported shape, so the walk below reaches
/// each of them.
fn populated_correlation() -> ArtifactCorrelationReport {
    ArtifactCorrelationReport {
        source_run: 7,
        mappings: 2,
        artifact_symbols: 3,
        mapped_symbols: 2,
        mapping_coverage: 0.5,
        mapped_symbol_bytes: 4,
        mapped_symbol_bytes_ratio: 0.5,
        unmapped_symbols: 1,
        unmapped_symbol_bytes: 2,
        unmapped_symbol_reasons: std::iter::once(("stripped".to_owned(), 1)).collect(),
        source_entities: 2,
        unmapped_sources: 1,
        unmapped_source_reasons: std::iter::once(("dead_code".to_owned(), 1)).collect(),
        clone_group_attributions: vec![CloneGroupAttributionReport {
            clone_group_fingerprint: fingerprint_hex([7; 16]),
            source_build_variant_fingerprint: fingerprint_hex([4; 16]),
            members: 2,
            attributed_noncanonical_members: 1,
            duplicated_bytes: None,
            estimated_duplicated_bytes: Some(9),
            containing_symbols: 1,
            containing_symbol_bytes: Some(12),
            clone_confidence: 1.0,
        }],
        estimated_refactor_savings: vec![CloneGroupSavingsReport {
            clone_group_fingerprint: fingerprint_hex([7; 16]),
            source_build_variant_fingerprint: fingerprint_hex([4; 16]),
            artifact_build_variant_fingerprint: fingerprint_hex([5; 16]),
            duplicated_bytes: 9,
            duplicated_bytes_basis: AttributionBasis::LineProportional,
            estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes(9),
            mapping_confidence: EvidenceConfidence::Medium,
            clone_confidence: 1.0,
            model_confidence: EvidenceConfidence::Low,
            savings_confidence: EvidenceConfidence::Low,
            assumptions: vec![
                RefactorSavingsAssumption::SharedImplementationRetainsCopies { copies: 1 },
                RefactorSavingsAssumption::CallOverheadPerReplacedMember { bytes: 0 },
                RefactorSavingsAssumption::InliningOutcomeUnknown,
                RefactorSavingsAssumption::LinkerIcfOutcomeUnknown,
                RefactorSavingsAssumption::AttributionIsLineProportional,
            ],
            model_schema_version: "refactor-savings-model-v1",
        }],
        generic_origins: vec![GenericOriginReport {
            definition: "crate::make".to_owned(),
            origin_fingerprint: fingerprint_hex([1; 16]),
            origin_build_variant_fingerprint: fingerprint_hex([4; 16]),
            instantiations: 1,
            translation_units: 1,
            artifact_symbols: 1,
            observed_symbol_bytes: 4,
            normalized_instruction_duplicated_bytes: 2,
            retained_size_sum: Some(4),
            specializations: vec![GenericSpecializationReport {
                instantiation_key: "crate::make<u32>".to_owned(),
                type_arguments: vec!["u32".to_owned()],
                artifact_symbols: 1,
                translation_units: 1,
                observed_symbol_bytes: 4,
            }],
        }],
        macro_origins: vec![MacroOriginReport {
            origin_fingerprint: fingerprint_hex([2; 16]),
            origin_build_variant_fingerprint: fingerprint_hex([4; 16]),
            definition_paths: vec!["src/lib.rs".to_owned()],
            artifact_symbols: 1,
            observed_symbol_bytes: 4,
        }],
        multiply_emitted_units: vec![MultiplyEmittedUnitReport {
            source_fingerprint: fingerprint_hex([3; 16]),
            source_build_variant_fingerprint: fingerprint_hex([4; 16]),
            name: Some("firstEntryFrom".to_owned()),
            emitted_bodies: 3,
            observed_symbol_bytes: 12,
            mapping_confidence: EvidenceConfidence::Low,
        }],
    }
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
        body_fingerprint: None,
        inline_stack: Vec::new(),
    }
}

/// Every size category reaches text, CSV and JSON under the name the schema
/// declares, carrying its own value.
///
/// The categories are read back out of the serialized classification rather
/// than listed here, so a category the classification gains and one rendering
/// then omits fails this test instead of passing unremarked. Each field is
/// given a distinct value, so a rendering that reached for the neighbouring
/// field would report the neighbour's number and be caught.
#[test]
fn savings_categories_remain_distinct_in_every_artifact_report_format() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let mut report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    report.sizes = metrics::SizeClassification {
        observed_bytes: 100,
        duplicated_bytes: 80,
        // Normalized duplication stands beside byte-identical duplication and
        // is added into neither it nor any savings value: it is reached
        // through a rewriting rule, not observed directly.
        duplicated_bytes_normalized: Some(90),
        retained_bytes: Some(70),
        shared_dependency_bytes: Some(60),
        duplicated_data_bytes: Some(50),
        upper_bound_savings_bytes: Some(40),
        estimated_refactor_savings_bytes: Some(EstimatedRefactorSavingsBytes(30)),
        verified_savings_bytes: Some(VerifiedSavingsBytes(20)),
        clone_confidence: EvidenceConfidence::High,
        savings_confidence: EvidenceConfidence::Low,
        assumptions: Vec::new(),
    };

    let json = serde_json::to_value(&report).unwrap();
    let categories: Vec<(String, i64)> = json["sizes"]
        .as_object()
        .expect("the classification serializes as an object")
        .iter()
        .filter_map(|(name, value)| Some((name.clone(), value.as_i64()?)))
        .collect();
    assert!(
        !categories.is_empty(),
        "no size category was recovered from the classification"
    );
    let distinct: BTreeSet<i64> = categories.iter().map(|(_, value)| *value).collect();
    assert_eq!(
        distinct.len(),
        categories.len(),
        "two categories share one value, so a rendering could confuse them: {categories:?}"
    );

    let text = rendered_text(&report, false);
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut rows = csv.lines();
    let header: Vec<_> = rows.next().unwrap().split(',').collect();
    let summary: Vec<_> = rows.next().unwrap().split(',').collect();

    for (name, value) in &categories {
        assert!(
            text.contains(&format!("  {name}: {value}")),
            "the text report omits {name}"
        );
        let index = header
            .iter()
            .position(|column| column == name)
            .unwrap_or_else(|| unreachable!("the CSV header omits {name}"));
        assert_eq!(summary[index], value.to_string(), "unexpected CSV {name}");
        assert_eq!(json["sizes"][name], *value, "unexpected JSON {name}");
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

/// Read one rendered artifact CSV into its records.
fn artifact_csv_records(report: &ArtifactReport) -> Vec<Vec<String>> {
    let mut rendered = Vec::new();
    render_csv(report, &mut rendered).unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    let mut lines = rendered.lines();
    assert_eq!(lines.next().unwrap(), ARTIFACT_CSV_HEADER.join(","));
    let records: Vec<Vec<String>> = lines.map(artifact_csv_fields).collect();
    for record in &records {
        assert_eq!(record.len(), ARTIFACT_CSV_HEADER.len(), "{record:?}");
    }
    records
}

/// Read one rendered comparison CSV into its records.
fn compare_csv_records(report: &ArtifactComparisonReport) -> Vec<Vec<String>> {
    let mut rendered = Vec::new();
    render_compare_csv(report, &mut rendered).unwrap();
    let rendered = String::from_utf8(rendered).unwrap();
    let mut lines = rendered.lines();
    assert_eq!(lines.next().unwrap(), COMPARE_CSV_HEADER.join(","));
    let records: Vec<Vec<String>> = lines.map(artifact_csv_fields).collect();
    for record in &records {
        assert_eq!(record.len(), COMPARE_CSV_HEADER.len(), "{record:?}");
    }
    records
}

/// Every record of one type in a rendered artifact CSV.
fn artifact_csv_records_of(report: &ArtifactReport, record_type: &str) -> Vec<Vec<String>> {
    artifact_csv_records(report)
        .into_iter()
        .filter(|record| record[column::RECORD_TYPE] == record_type)
        .collect()
}

/// The statements one rendered artifact CSV carries.
fn artifact_csv_assumptions(report: &ArtifactReport) -> Vec<String> {
    artifact_csv_records_of(report, "assumption")
        .into_iter()
        .map(|record| record[column::ASSUMPTION].clone())
        .collect()
}

/// The statements one rendered comparison CSV carries, warning included.
fn compare_csv_assumptions(report: &ArtifactComparisonReport) -> Vec<String> {
    compare_csv_records(report)
        .into_iter()
        .filter_map(
            |record| match record[compare_column::RECORD_TYPE].as_str() {
                "assumption" => Some(record[compare_column::ASSUMPTION].clone()),
                "build-variant-warning" => Some(record[compare_column::WARNING].clone()),
                _ => None,
            },
        )
        .collect()
}

/// The text a renderer produced, as one string.
fn rendered_text(report: &ArtifactReport, verbose: bool) -> String {
    let mut rendered = Vec::new();
    render_text(report, verbose, &mut rendered).unwrap();
    String::from_utf8(rendered).unwrap()
}

/// The comparison text a renderer produced, as one string.
fn rendered_compare_text(report: &ArtifactComparisonReport) -> String {
    let mut rendered = Vec::new();
    render_compare_text(report, &mut rendered).unwrap();
    String::from_utf8(rendered).unwrap()
}

/// One WASM artifact whose call graph resolves completely.
fn resolved_call_graph_artifact() -> ArtifactIr {
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.capabilities.call_graph = true;
    artifact.capabilities.independent_data_segments = true;
    artifact.observed_bytes = 128;
    artifact.symbols = vec![
        normalizable_symbol(10, &[1, 2], &[9]),
        normalizable_symbol(20, &[1, 3], &[9]),
    ];
    artifact.symbols[0].exported = true;
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: artifact.symbols[0].fingerprint,
        target: Some(artifact.symbols[1].fingerprint),
        unresolved: None,
    });
    artifact
        .sections
        .push(codehelion_artifact::ArtifactSection {
            name: Some(".text".to_owned()),
            offset: 0,
            size: 48,
            executable: true,
        });
    artifact
        .data_segments
        .push(codehelion_artifact::ArtifactDataSegment {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "data",
                b"0123456789abcdef",
            ),
            section: Some(1),
            offset: 64,
            bytes: b"0123456789abcdef".to_vec(),
        });
    artifact
}

/// Walking one artifact once must answer exactly what three separate walks
/// answered. Three walks were three chances to settle the same soundness
/// question differently, and the report showed all three answers side by side.
#[test]
fn one_call_graph_walk_answers_what_three_separate_walks_answered() {
    let unresolved = {
        let mut artifact = resolved_call_graph_artifact();
        artifact.calls.push(codehelion_artifact::ArtifactCall {
            caller: artifact.symbols[0].fingerprint,
            target: None,
            unresolved: None,
        });
        artifact
    };
    let no_call_edges = {
        let mut artifact = resolved_call_graph_artifact();
        artifact.capabilities.call_graph = false;
        artifact
    };
    for artifact in [resolved_call_graph_artifact(), unresolved, no_call_edges] {
        let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
        let duplicates = metrics::find_duplicates(&artifact);
        let data =
            metrics::find_duplicate_data(&artifact, metrics::DEFAULT_MIN_DUPLICATE_DATA_BYTES);
        let separate = metrics::classify_sizes_from_duplicates(&artifact, &duplicates, &data);

        assert_eq!(report.sizes.observed_bytes, separate.observed_bytes);
        assert_eq!(report.sizes.duplicated_bytes, separate.duplicated_bytes);
        assert_eq!(
            report.sizes.duplicated_bytes_normalized,
            separate.duplicated_bytes_normalized
        );
        assert_eq!(report.sizes.retained_bytes, separate.retained_bytes);
        assert_eq!(
            report.sizes.shared_dependency_bytes,
            separate.shared_dependency_bytes
        );
        assert_eq!(
            report.sizes.duplicated_data_bytes,
            separate.duplicated_data_bytes
        );
        assert_eq!(
            report.sizes.upper_bound_savings_bytes,
            separate.upper_bound_savings_bytes
        );
        assert_eq!(report.sizes.clone_confidence, separate.clone_confidence);
        assert_eq!(report.sizes.savings_confidence, separate.savings_confidence);
        // The report adds what its own fields leave out and drops nothing the
        // derivation stated.
        for assumption in &separate.assumptions {
            assert!(
                report.sizes.assumptions.contains(assumption),
                "{assumption:?} missing from {:?}",
                report.sizes.assumptions
            );
        }
        assert_eq!(report.dead_code, metrics::dead_code_candidates(&artifact));
        assert_eq!(report.retained_sizes, metrics::retained_sizes(&artifact));
    }
}

/// Installed ceilings are part of what a report says about itself, in every
/// format that report is written in.
#[test]
fn untrusted_containment_reaches_every_rendering() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_containment(Some(ArtifactContainment {
            max_input_bytes: 1024,
            worker_timeout_seconds: 10,
            worker_memory_limit_bytes: 4096,
            max_debug_derived_items: 1_024,
        }));

    assert!(rendered_text(&report, false).contains(
        "untrusted containment: input 1024 bytes, worker timeout 10s, worker memory 4096 bytes"
    ));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["containment"]["max_input_bytes"], 1024);
    let containment = artifact_csv_records_of(&report, "containment")
        .pop()
        .expect("one containment record");
    assert_eq!(containment[column::MAX_INPUT_BYTES], "1024");
    assert_eq!(containment[column::WORKER_TIMEOUT_SECONDS], "10");
    assert_eq!(containment[column::WORKER_MEMORY_LIMIT_BYTES], "4096");

    let mut comparison = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &artifact,
        None,
        FilePath::new("after.wasm"),
        &artifact,
        None,
    );
    comparison.containment = Some(ArtifactContainment {
        max_input_bytes: 2048,
        worker_timeout_seconds: 20,
        worker_memory_limit_bytes: 8192,
        max_debug_derived_items: 1_024,
    });
    assert!(rendered_compare_text(&comparison).contains(
        "untrusted containment: input 2048 bytes, worker timeout 20s, worker memory 8192 bytes"
    ));
    let json = serde_json::to_value(&comparison).unwrap();
    assert_eq!(json["containment"]["worker_memory_limit_bytes"], 8192);
    let containment = compare_csv_records(&comparison)
        .into_iter()
        .find(|record| record[compare_column::RECORD_TYPE] == "containment")
        .expect("one containment record");
    assert_eq!(containment[compare_column::MAX_INPUT_BYTES], "2048");
    assert_eq!(containment[compare_column::WORKER_TIMEOUT_SECONDS], "20");
    assert_eq!(
        containment[compare_column::WORKER_MEMORY_LIMIT_BYTES],
        "8192"
    );
}

mod assumption;
mod calibration;
mod compare;
mod csv;
mod input;
mod schema;
mod source_map;
mod text;
