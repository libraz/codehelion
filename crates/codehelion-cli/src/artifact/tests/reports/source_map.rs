//! WASM source-map resolution and the outcome each reference reports.

use super::*;
use std::fs;

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

/// The outcome of each declared source-map reference is evidence, and a reader
/// of any one format can see it.
#[test]
fn source_map_outcomes_reach_every_rendering() {
    let mut artifact = resolved_call_graph_artifact();
    artifact
        .source_mappings
        .push(codehelion_artifact::ArtifactSourceMapping {
            uri: "module.wasm.map".to_owned(),
        });
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_source_maps(vec![
            SourceMapResolution {
                uri: "module.wasm.map".to_owned(),
                status: SourceMapResolutionStatus::Resolved {
                    local_path: "/tmp/module.wasm.map".to_owned(),
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
        ]);

    let text = rendered_text(&report, false);
    assert!(
        text.contains("module.wasm.map: resolved to /tmp/module.wasm.map (1 sources)"),
        "{text}"
    );
    assert!(
        text.contains("https://example.invalid/module.wasm.map: unavailable (non_local_reference)"),
        "{text}"
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["source_maps"][0]["status"], "resolved");
    assert_eq!(json["source_maps"][1]["reason"], "non_local_reference");
    let maps = artifact_csv_records_of(&report, "source-map");
    assert_eq!(maps.len(), 2);
    assert_eq!(maps[0][column::KIND], "resolved");
    assert_eq!(
        maps[0][column::SOURCE_MAP_LOCAL_PATH],
        "/tmp/module.wasm.map"
    );
    assert_eq!(maps[0][column::SOURCE_MAP_SOURCES], "src/lib.rs");
    assert_eq!(maps[1][column::KIND], "non_local_reference");
    assert_eq!(
        maps[1][column::SOURCE_MAP_URI],
        "https://example.invalid/module.wasm.map"
    );
}
