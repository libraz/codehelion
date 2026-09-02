//! Reported JSON against the shipped schema declarations.

use super::*;

#[test]
fn artifact_and_calibration_json_reports_validate_against_shipped_schemas() {
    let artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    let artifact_report =
        ArtifactReport::from_ir(std::path::Path::new("fixture.wasm"), &artifact, None, None);
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-report-v2.schema.json",
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

/// Every field the artifact report writes is declared where it is written.
///
/// The schema is the contract a consumer validates against, and a reporter
/// that grows a field the schema never learned about makes that consumer treat
/// real output as unknown. Walking the serialized report against the shipped
/// declarations catches the two drifting apart.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the walk names every reported object beside its schema declaration"
)]
fn artifact_json_field_names_appear_in_the_shipped_schema() {
    let schema: serde_json::Value = serde_json::from_str(ARTIFACT_REPORT_JSON_SCHEMA).unwrap();
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        ARTIFACT_REPORT_SCHEMA_VERSION
    );
    let mut artifact = WasmBackend.parse(b"\0asm\x01\0\0\0").unwrap();
    artifact.capabilities.call_graph = true;
    artifact.capabilities.normalized_duplicates = true;
    artifact.observed_bytes = 128;
    artifact.architecture = Some("wasm32".to_owned());
    artifact.skipped_architectures = vec!["wasm64".to_owned()];
    artifact.symbols = vec![
        normalizable_symbol(10, &[1, 2], &[9]),
        normalizable_symbol(20, &[1, 3], &[9]),
        normalizable_symbol(30, &[1, 2], &[9]),
    ];
    artifact.symbols[0].exported = true;
    artifact.symbols[0].name = Some("root".to_owned());
    artifact.entry_points.push(artifact.symbols[0].fingerprint);
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: artifact.symbols[0].fingerprint,
        target: Some(artifact.symbols[1].fingerprint),
        unresolved: None,
    });
    artifact
        .sections
        .push(codehelion_artifact::ArtifactSection {
            name: Some(".text".to_owned()),
            offset: 16,
            size: 32,
            executable: true,
        });
    artifact.imports.push(codehelion_artifact::ArtifactImport {
        module: Some("env".to_owned()),
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
    for offset in [64_u64, 96] {
        artifact
            .data_segments
            .push(codehelion_artifact::ArtifactDataSegment {
                fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                    "data",
                    b"0123456789abcdef",
                ),
                section: Some(2),
                offset,
                bytes: b"0123456789abcdef".to_vec(),
            });
    }
    artifact
        .archive_members
        .push(codehelion_artifact::ArtifactArchiveMember {
            name: "member.o".to_owned(),
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "archive-member",
                b"member",
            ),
            offset: Some(32),
            size: Some(8),
            format: Some(BinaryFormat::Wasm),
            thin: false,
            parse_error: None,
        });
    artifact
        .source_mappings
        .push(codehelion_artifact::ArtifactSourceMapping {
            uri: "module.wasm.map".to_owned(),
        });

    let mut report = ArtifactReport::from_ir(
        std::path::Path::new("fixture.wasm"),
        &artifact,
        Some(3),
        Some(ComparisonBuildVariant {
            manifest_path: "build-variant.json".to_owned(),
            fingerprint: fingerprint_hex([6; 16]),
        }),
    )
    .with_containment(Some(ArtifactContainment {
        max_input_bytes: 1024,
        worker_timeout_seconds: 10,
        worker_memory_limit_bytes: 4096,
        max_debug_derived_items: 1_024,
    }))
    .with_source_maps(vec![
        SourceMapResolution {
            uri: "module.wasm.map".to_owned(),
            status: SourceMapResolutionStatus::Resolved {
                local_path: "module.wasm.map".to_owned(),
                sources: vec!["src/lib.rs".to_owned()],
                locations: Vec::new(),
            },
        },
        SourceMapResolution {
            uri: "https://example.invalid/module.wasm.map".to_owned(),
            status: SourceMapResolutionStatus::Unavailable {
                reason: "non_local_reference",
            },
        },
    ])
    .with_correlation(Some(populated_correlation()));
    report.retained_sizes = Some(vec![metrics::RetainedSize {
        symbol: artifact.symbols[0].fingerprint,
        retained_bytes: 2,
    }]);

    let value = serde_json::to_value(&report).unwrap();
    assert!(value["symbols"].as_array().is_some_and(|s| !s.is_empty()));
    assert!(value["duplicate_groups"]["exact"][0].is_object());
    assert!(value["duplicate_groups"]["normalized"][0].is_object());
    assert!(value["duplicate_groups"]["data"][0].is_object());
    assert!(value["dead_code"].is_object());
    let defs = &schema["$defs"];
    let correlation = &defs["correlation"]["properties"];
    let savings = &correlation["estimated_refactor_savings"]["items"]["properties"];
    let generic = &correlation["generic_origins"]["items"]["properties"];
    let checks = [
        (&value, &schema["properties"]),
        (&value["sizes"], &defs["sizes"]["properties"]),
        (&value["containment"], &defs["containment"]["properties"]),
        (
            &value["build_variant"],
            &defs["build_variant"]["properties"],
        ),
        (&value["capabilities"], &defs["capabilities"]["properties"]),
        (&value["dead_code"], &defs["dead_code"]["properties"]),
        (&value["symbols"][0], &defs["symbol"]["properties"]),
        (&value["section_details"][0], &defs["section"]["properties"]),
        (&value["import_details"][0], &defs["import"]["properties"]),
        (
            &value["relocation_details"][0],
            &defs["relocation"]["properties"],
        ),
        (
            &value["data_segment_details"][0],
            &defs["data_segment"]["properties"],
        ),
        (
            &value["archive_members"][0],
            &defs["archive_member"]["properties"],
        ),
        (&value["source_maps"][0], &defs["source_map"]["properties"]),
        (&value["source_maps"][1], &defs["source_map"]["properties"]),
        (
            &value["retained_sizes"][0],
            &defs["retained_size"]["properties"],
        ),
        (
            &value["duplicates"],
            &defs["duplicate_summary"]["properties"],
        ),
        (
            &value["duplicate_groups"],
            &defs["duplicate_groups"]["properties"],
        ),
        (
            &value["duplicate_groups"]["exact"][0],
            &defs["duplicate_group"]["properties"],
        ),
        (
            &value["duplicate_groups"]["exact"][0]["members"][0],
            &defs["duplicate_group"]["properties"]["members"]["items"]["properties"],
        ),
        (&value["correlation"], correlation),
        (
            &value["correlation"]["clone_group_attributions"][0],
            &correlation["clone_group_attributions"]["items"]["properties"],
        ),
        (
            &value["correlation"]["estimated_refactor_savings"][0],
            savings,
        ),
        (
            &value["correlation"]["estimated_refactor_savings"][0]["assumptions"][0],
            &savings["assumptions"]["items"]["properties"],
        ),
        (&value["correlation"]["generic_origins"][0], generic),
        (
            &value["correlation"]["generic_origins"][0]["specializations"][0],
            &generic["specializations"]["items"]["properties"],
        ),
        (
            &value["correlation"]["macro_origins"][0],
            &correlation["macro_origins"]["items"]["properties"],
        ),
    ];
    for (object, properties) in checks {
        let keys = object.as_object().expect("the fixture writes an object");
        for key in keys.keys() {
            assert!(
                properties.get(key).is_some(),
                "field {key:?} missing from the shipped schema"
            );
        }
    }
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-report-v2.schema.json",
        ARTIFACT_REPORT_JSON_SCHEMA,
        &value,
    );
}
