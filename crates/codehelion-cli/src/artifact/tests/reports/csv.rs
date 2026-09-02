//! CSV rendering: quoting, record kinds, and the columns each one fills.

use super::*;
use crate::artifact::model::ARTIFACT_CSV_HEADER;
use crate::artifact::render::{attribution_column, stated_bytes};
use codehelion_artifact::metrics::ReportedSize;

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

/// A CSV reader gets every size category the other two formats publish.
#[test]
fn the_csv_summary_carries_every_size_category() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None);
    let summary = artifact_csv_records_of(&report, "summary")
        .pop()
        .expect("one summary record");

    // Named for every category, so it checks every category: the one that
    // went missing before was reachable in the text and JSON views while the
    // record a consumer parses left it out, and a test naming one column
    // could not have seen that.
    let text = rendered_text(&report, false);
    let json = serde_json::to_value(&report).unwrap();
    for (category, bytes) in report.sizes.stated() {
        assert!(
            ARTIFACT_CSV_HEADER.contains(&category.key()),
            "no column carries {}",
            category.key()
        );
        let column = ARTIFACT_CSV_HEADER
            .iter()
            .position(|name| *name == category.key())
            .expect("the header was just checked to hold this name");
        assert_eq!(
            summary[column],
            stated_bytes(bytes),
            "the summary record states {}",
            category.key()
        );
        assert!(
            text.contains(&format!("  {}: {}", category.key(), stated_bytes(bytes))),
            "the text report states {}",
            category.key()
        );
        assert!(
            json["sizes"].get(category.key()).is_some(),
            "the JSON report states {}",
            category.key()
        );
    }
    assert_eq!(
        summary[column::CLONE_CONFIDENCE],
        format!("{:?}", report.sizes.clone_confidence)
    );
    assert_eq!(
        summary[column::SAVINGS_CONFIDENCE],
        format!("{:?}", report.sizes.savings_confidence)
    );
    assert_eq!(
        summary[column::CODE_SECTION_BYTES],
        report.code_section_bytes.to_string()
    );
    assert_eq!(
        summary[column::DATA_SEGMENT_BYTES],
        report.data_segment_bytes.to_string()
    );
}

/// A report exercising every kind of record the CSV can write.
///
/// Some kinds come out of the analysis and some are attached afterwards, so
/// the ones the fixture cannot produce are set on the report directly. What
/// matters is that each kind appears: a kind nothing exercises is a
/// declaration nothing checks.
fn report_of_every_record_kind() -> ArtifactReport {
    let artifact = resolved_call_graph_artifact();
    let mut report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_correlation(Some(populated_correlation()));
    report.containment = Some(ArtifactContainment {
        max_input_bytes: 4096,
        worker_timeout_seconds: 30,
        worker_memory_limit_bytes: 8192,
        max_debug_derived_items: 4096,
    });
    report.build_variant = Some(
        BuildVariantEvidence {
            manifest_path: "build-variant.json".to_owned(),
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "artifact-build-variant",
                b"variant",
            ),
        }
        .for_report(),
    );
    report.archive_members = vec![ArchiveMemberReport {
        name: "member.o".to_owned(),
        fingerprint: "bb".repeat(16),
        offset: Some(32),
        size: Some(8),
        format: Some(BinaryFormat::Elf),
        thin: false,
        parse_error: None,
    }];
    report.import_details = vec![ImportReport {
        module: Some("env".to_owned()),
        name: Some("host".to_owned()),
        kind: codehelion_artifact::ArtifactImportKind::Function,
    }];
    report.relocation_details = vec![RelocationReport {
        section: Some(1),
        offset: 4,
        kind: "call".to_owned(),
        target: Some("cc".repeat(16)),
    }];
    report.source_maps = vec![SourceMapResolution {
        uri: "app.wasm.map".to_owned(),
        status: SourceMapResolutionStatus::Resolved {
            local_path: "dist/app.wasm.map".to_owned(),
            sources: vec!["src/app.rs".to_owned()],
            locations: Vec::new(),
        },
    }];
    report.dead_code = Some(metrics::DeadCodeReport {
        symbols: vec![artifact.symbols[0].fingerprint],
        definitive: true,
        assumptions: Vec::new(),
    });
    report.retained_sizes = Some(vec![metrics::RetainedSize {
        symbol: artifact.symbols[0].fingerprint,
        retained_bytes: 4,
    }]);
    report
}

/// No record fills a column its kind was not declared to carry, and every
/// declared kind is one this check actually meets.
///
/// The CSV is one wide row and each kind of record fills a subset of it, so
/// nothing about a row says which columns belong to it. A writer that started
/// filling a column meant for another kind would produce a document a consumer
/// reads as saying something it does not.
#[test]
fn every_csv_record_fills_only_the_columns_its_kind_declares() {
    let report = report_of_every_record_kind();
    let mut met: BTreeSet<&str> = BTreeSet::new();
    for record in artifact_csv_records(&report) {
        let kind = record[column::RECORD_TYPE].as_str();
        assert!(
            RECORD_COLUMNS.iter().any(|entry| entry.record_type == kind),
            "no columns are declared for a {kind} record"
        );
        let declared = RECORD_COLUMNS
            .iter()
            .find(|entry| entry.record_type == kind)
            .expect("the declarations were just checked to hold this kind");
        met.insert(declared.record_type);
        for (index, field) in record.iter().enumerate() {
            assert!(
                field.is_empty()
                    || EVERY_RECORD.contains(&index)
                    || declared.columns.contains(&index),
                "a {kind} record fills {}, which its kind does not carry",
                ARTIFACT_CSV_HEADER[index]
            );
        }
    }
    let unmet: Vec<&str> = RECORD_COLUMNS
        .iter()
        .map(|entry| entry.record_type)
        .filter(|kind| !met.contains(kind))
        .collect();
    assert!(
        unmet.is_empty(),
        "no record of these kinds was produced, so their columns are declared and unchecked: {unmet:?}"
    );
}

/// A named CSV column carries the quantity its name states, for every record
/// type that fills it.
#[test]
fn csv_columns_carry_the_quantity_their_name_states() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_correlation(Some(populated_correlation()));
    let records = artifact_csv_records(&report);

    let attribution = records
        .iter()
        .find(|record| record[column::RECORD_TYPE] == "clone-group-attribution")
        .expect("one attribution record");
    // The text states "X / Y noncanonical members attributed"; both numbers
    // are recoverable, and neither one occupies the instantiation column.
    assert_eq!(attribution[column::MEMBERS], "2");
    assert_eq!(attribution[column::ATTRIBUTED_NONCANONICAL_MEMBERS], "1");
    assert_eq!(attribution[column::INSTANTIATIONS], "");

    let macro_origin = records
        .iter()
        .find(|record| record[column::RECORD_TYPE] == "macro-origin")
        .expect("one macro origin record");
    assert_eq!(macro_origin[column::ARTIFACT_SYMBOLS], "1");
    assert_eq!(macro_origin[column::DEFINITION_PATH_COUNT], "1");
    assert_eq!(macro_origin[column::INSTANTIATIONS], "");
    assert_eq!(macro_origin[column::TRANSLATION_UNITS], "");

    // Only a generic origin counts instantiations.
    for record in &records {
        if record[column::INSTANTIATIONS].is_empty() {
            continue;
        }
        assert!(
            record[column::RECORD_TYPE].starts_with("generic-"),
            "{record:?}"
        );
    }
    let generic = records
        .iter()
        .find(|record| record[column::RECORD_TYPE] == "generic-origin")
        .expect("one generic origin record");
    assert_eq!(generic[column::INSTANTIATIONS], "1");
    assert_eq!(generic[column::ARTIFACT_SYMBOLS], "1");
    assert_eq!(generic[column::RETAINED_BYTES], "4");
}

/// Every byte count one clone-group attribution states reaches all three
/// renderings, under the name that identifies it.
///
/// The clone-group counterpart of the artifact-wide check: three numbers of
/// three different kinds sit on one record, and a reader taking any of them by
/// position must never receive another.
#[test]
fn every_clone_group_byte_count_reaches_every_rendering() {
    let artifact = resolved_call_graph_artifact();
    let report = ArtifactReport::from_ir(FilePath::new("fixture.wasm"), &artifact, None, None)
        .with_correlation(Some(populated_correlation()));
    let record = artifact_csv_records(&report)
        .into_iter()
        .find(|record| record[column::RECORD_TYPE] == "clone-group-attribution")
        .expect("one attribution record");
    let text = rendered_text(&report, false);
    let json = serde_json::to_value(&report).unwrap();
    let attribution = &report
        .correlation
        .as_ref()
        .expect("the report carries its correlation")
        .clone_group_attributions[0];

    for (category, bytes) in attribution.stated() {
        assert!(
            ARTIFACT_CSV_HEADER.contains(&category.key()),
            "no column carries {}",
            category.key()
        );
        assert_eq!(
            record[attribution_column(category)],
            bytes.map_or_else(String::new, |bytes| bytes.to_string()),
            "the attribution record states {}",
            category.key()
        );
        assert!(
            json["correlation"]["clone_group_attributions"][0]
                .get(category.key())
                .is_some(),
            "the JSON report states {}",
            category.key()
        );
        if let Some(bytes) = bytes {
            assert!(
                text.contains(&bytes.to_string()),
                "the text report states {}",
                category.key()
            );
        }
    }
}
