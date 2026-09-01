//! `artifact analyze` resolves a WASM module's declared source map the same
//! way no matter how the artifact path on the command line is spelled: a bare
//! filename resolved against the working directory, an explicit `./` relative
//! path, and an absolute path all name the same file and its same sibling map.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use assert_cmd::Command;

fn cmd() -> Command {
    Command::cargo_bin("codehelion").expect("binary should build")
}

/// A minimal WASM module declaring a `sourceMappingURL` custom section.
///
/// Hand-built rather than reusing a real toolchain's output: only the magic
/// header, version, and one custom section matter to the resolution this
/// covers, and every length here is a single LEB128 byte because the fixture
/// name and URI are both short.
fn wasm_with_source_mapping_url(uri: &str) -> Vec<u8> {
    let mut content = vec![16u8]; // length of b"sourceMappingURL"
    content.extend_from_slice(b"sourceMappingURL");
    content.extend_from_slice(uri.as_bytes());
    assert!(
        content.len() < 128,
        "fixture section is too long for a single-byte LEB128 length"
    );
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    module.push(0); // custom section id
    module.push(u8::try_from(content.len()).expect("fixture section is short"));
    module.extend_from_slice(&content);
    module
}

fn resolved_source_map_status(
    directory: &std::path::Path,
    artifact_argument: &str,
    database: &std::path::Path,
) -> String {
    let output = cmd()
        .current_dir(directory)
        .args([
            "artifact",
            "analyze",
            artifact_argument,
            "--format",
            "json",
            "--db",
        ])
        .arg(database)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    json["source_maps"][0]["status"]
        .as_str()
        .unwrap_or_else(|| panic!("no source_maps[0].status in {json}"))
        .to_owned()
}

#[test]
fn a_bare_filename_resolves_the_same_source_map_as_an_explicit_or_absolute_path() {
    let directory = tempfile::tempdir().expect("fixture directory");
    std::fs::write(
        directory.path().join("module.wasm"),
        wasm_with_source_mapping_url("module.wasm.map"),
    )
    .expect("write wasm fixture");
    std::fs::write(
        directory.path().join("module.wasm.map"),
        br#"{"version":3,"sources":["src/lib.rs"],"names":[],"mappings":"YAIA"}"#,
    )
    .expect("write source map fixture");

    let database = directory.path().join("artifact.sqlite");
    let bare = resolved_source_map_status(directory.path(), "module.wasm", &database);
    let explicit_relative =
        resolved_source_map_status(directory.path(), "./module.wasm", &database);
    let absolute = resolved_source_map_status(
        directory.path(),
        directory
            .path()
            .join("module.wasm")
            .to_str()
            .expect("utf-8 fixture path"),
        &database,
    );

    assert_eq!(bare, "resolved", "a bare filename must resolve its map");
    assert_eq!(explicit_relative, "resolved");
    assert_eq!(absolute, "resolved");
}
