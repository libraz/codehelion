//! Artifact input selection and output writing.

use super::*;
use crate::cli::{DEFAULT_ARTIFACT_MAX_BYTES, DEFAULT_ARTIFACT_TIMEOUT_SECONDS};
use std::fs;

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
fn input_limit_is_checked_before_reading_or_parsing() {
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), b"more than eight bytes").unwrap();
    let error = inspect(file.path(), 8, None, None, None, false).unwrap_err();
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
