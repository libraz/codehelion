//! Compressed sizes: the three renderings state the same values.

use super::*;
use codehelion_artifact::compression::{CompressedSize, CompressionAlgorithm};

const NOTE: &str = "  note: the compressed size covers the whole artifact; it is not divided among symbols, and an external compressor at the same level can differ by a fraction of a percent";

fn gzip(bytes: u64) -> CompressedSize {
    CompressedSize {
        algorithm: CompressionAlgorithm::Gzip,
        parameters: "level 9".to_owned(),
        encoder: "flate2 (miniz_oxide)".to_owned(),
        bytes,
    }
}

fn brotli(bytes: u64) -> CompressedSize {
    CompressedSize {
        algorithm: CompressionAlgorithm::Brotli,
        parameters: "quality 11, window 22".to_owned(),
        encoder: "brotli (rust)".to_owned(),
        bytes,
    }
}

fn measured(sizes: Vec<CompressedSize>) -> ArtifactIr {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.compressed_sizes = sizes;
    artifact
}

fn report_of(artifact: &ArtifactIr) -> ArtifactReport {
    ArtifactReport::from_ir(FilePath::new("fixture.wasm"), artifact, None, None)
}

fn comparison_of(before: &ArtifactIr, after: &ArtifactIr) -> ArtifactComparisonReport {
    ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        before,
        None,
        FilePath::new("after.wasm"),
        after,
        None,
    )
}

#[test]
fn an_analysis_states_each_compressed_size_in_text_json_and_csv() {
    let report = report_of(&measured(vec![gzip(209_710), brotli(180_001)]));

    let text = rendered_text(&report, false);
    assert!(
        text.contains("\ncompressed bytes (gzip, level 9, flate2 (miniz_oxide)): 209710\n"),
        "{text}"
    );
    assert!(
        text.contains(
            "\ncompressed bytes (brotli, quality 11, window 22, brotli (rust)): 180001\n"
        ),
        "{text}"
    );
    assert_eq!(text.matches(NOTE).count(), 1, "{text}");

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["compressed_sizes"],
        serde_json::json!([
            {
                "algorithm": "gzip",
                "parameters": "level 9",
                "encoder": "flate2 (miniz_oxide)",
                "bytes": 209_710,
            },
            {
                "algorithm": "brotli",
                "parameters": "quality 11, window 22",
                "encoder": "brotli (rust)",
                "bytes": 180_001,
            },
        ])
    );

    let records = artifact_csv_records_of(&report, "compressed-size");
    assert_eq!(records.len(), 2);
    assert_eq!(records[0][column::COMPRESSION_ALGORITHM], "gzip");
    assert_eq!(records[0][column::COMPRESSION_PARAMETERS], "level 9");
    assert_eq!(
        records[0][column::COMPRESSION_ENCODER],
        "flate2 (miniz_oxide)"
    );
    assert_eq!(records[0][column::COMPRESSED_BYTES], "209710");
    assert_eq!(records[1][column::COMPRESSION_ALGORITHM], "brotli");
    assert_eq!(
        records[1][column::COMPRESSION_PARAMETERS],
        "quality 11, window 22"
    );
    assert_eq!(records[1][column::COMPRESSED_BYTES], "180001");
    // The records follow the summary directly.
    let kinds: Vec<String> = artifact_csv_records(&report)
        .into_iter()
        .map(|record| record[column::RECORD_TYPE].clone())
        .collect();
    assert_eq!(
        &kinds[..3],
        ["summary", "compressed-size", "compressed-size"]
    );
}

#[test]
fn an_analysis_without_a_measurement_states_no_compressed_size_anywhere() {
    let report = report_of(&measured(Vec::new()));

    assert!(!rendered_text(&report, false).contains("compressed bytes"));
    assert!(!rendered_text(&report, false).contains("note: the compressed size"));
    assert_eq!(
        serde_json::to_value(&report).unwrap()["compressed_sizes"],
        serde_json::json!([])
    );
    assert_eq!(artifact_csv_records_of(&report, "compressed-size").len(), 0);
}

#[test]
fn a_comparison_states_the_signed_difference_in_text_json_and_csv() {
    let report = comparison_of(
        &measured(vec![gzip(209_828), brotli(100)]),
        &measured(vec![gzip(209_710), brotli(130)]),
    );

    let text = rendered_compare_text(&report);
    assert!(
        text.contains(
            "\ncompressed bytes (gzip, level 9, flate2 (miniz_oxide)): 209828 before, 209710 after, -118 bytes (smaller)\n"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "\ncompressed bytes (brotli, quality 11, window 22, brotli (rust)): 100 before, 130 after, +30 bytes (larger)\n"
        ),
        "{text}"
    );
    let data = text.find("data segment bytes:").unwrap();
    let compressed = text.find("compressed bytes (").unwrap();
    assert!(data < compressed, "{text}");

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["compressed_deltas"][0],
        serde_json::json!({
            "algorithm": "gzip",
            "parameters": "level 9",
            "encoder": "flate2 (miniz_oxide)",
            "before_bytes": 209_828,
            "after_bytes": 209_710,
            "delta_bytes": -118,
        })
    );
    assert_eq!(json["compressed_deltas"][1]["delta_bytes"], 30);

    let records: Vec<Vec<String>> = compare_csv_records(&report)
        .into_iter()
        .filter(|record| record[compare_column::RECORD_TYPE] == "compressed-delta")
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0][compare_column::COMPRESSION_ALGORITHM], "gzip");
    assert_eq!(
        records[0][compare_column::BEFORE_COMPRESSED_BYTES],
        "209828"
    );
    assert_eq!(records[0][compare_column::AFTER_COMPRESSED_BYTES], "209710");
    assert_eq!(records[0][compare_column::COMPRESSED_DELTA_BYTES], "-118");
    assert_eq!(records[1][compare_column::COMPRESSED_DELTA_BYTES], "30");
}

#[test]
fn a_comparison_without_a_difference_in_compressed_size_says_so() {
    let report = comparison_of(&measured(vec![gzip(7)]), &measured(vec![gzip(7)]));
    assert!(
        rendered_compare_text(&report).contains("7 before, 7 after, +0 bytes (no change)"),
        "{}",
        rendered_compare_text(&report)
    );
}

#[test]
fn a_comparison_states_only_the_settings_measured_on_both_sides() {
    let report = comparison_of(
        &measured(vec![gzip(10), brotli(5)]),
        &measured(vec![gzip(12)]),
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["compressed_deltas"].as_array().unwrap().len(), 1);
    assert_eq!(json["compressed_deltas"][0]["algorithm"], "gzip");

    let mut other_level = gzip(12);
    other_level.parameters = "level 6".to_owned();
    let report = comparison_of(&measured(vec![gzip(10)]), &measured(vec![other_level]));
    assert_eq!(
        serde_json::to_value(&report).unwrap()["compressed_deltas"],
        serde_json::json!([])
    );
}

#[test]
fn a_comparison_without_a_measurement_states_no_compressed_size_anywhere() {
    let report = comparison_of(&measured(Vec::new()), &measured(Vec::new()));
    assert!(!rendered_compare_text(&report).contains("compressed bytes"));
    assert_eq!(
        serde_json::to_value(&report).unwrap()["compressed_deltas"],
        serde_json::json!([])
    );
    assert!(
        compare_csv_records(&report)
            .iter()
            .all(|record| record[compare_column::RECORD_TYPE] != "compressed-delta")
    );
}

#[test]
fn the_compression_columns_keep_their_positions_in_each_header() {
    for (header, names) in [
        (
            ARTIFACT_CSV_HEADER,
            [
                (column::COMPRESSION_ALGORITHM, "compression_algorithm"),
                (column::COMPRESSION_PARAMETERS, "compression_parameters"),
                (column::COMPRESSION_ENCODER, "compression_encoder"),
                (column::COMPRESSED_BYTES, "compressed_bytes"),
            ]
            .as_slice(),
        ),
        (
            COMPARE_CSV_HEADER,
            [
                (
                    compare_column::COMPRESSION_ALGORITHM,
                    "compression_algorithm",
                ),
                (
                    compare_column::COMPRESSION_PARAMETERS,
                    "compression_parameters",
                ),
                (compare_column::COMPRESSION_ENCODER, "compression_encoder"),
                (
                    compare_column::BEFORE_COMPRESSED_BYTES,
                    "before_compressed_bytes",
                ),
                (
                    compare_column::AFTER_COMPRESSED_BYTES,
                    "after_compressed_bytes",
                ),
                (
                    compare_column::COMPRESSED_DELTA_BYTES,
                    "compressed_delta_bytes",
                ),
            ]
            .as_slice(),
        ),
    ] {
        for (index, name) in names {
            assert_eq!(header[*index], *name);
        }
        let first = names[0].0;
        // Columns are only appended, so later quantities follow these.
        assert!(header.len() >= first + names.len());
    }
}
