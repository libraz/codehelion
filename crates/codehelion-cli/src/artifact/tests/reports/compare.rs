//! Comparison reports: symbol pairing, deltas, and comparison rendering.

use super::*;

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
        body_fingerprint: None,
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
        artifact_analysis_id: 11,
        matching_analyses: 1,
        already_recorded: false,
    });
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["calibration"]["absolute_error_bytes"], 3);
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-comparison-report-v2.schema.json",
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

/// Inserting a function moves every later function index and every call
/// immediate that names one, and neither belongs to a symbol's identity.
///
/// Both modules go through the parser, so the index assignment under test is
/// the one the parser performs. The assertions name the symbols that did not
/// change rather than the size of the shift, so the property holds however far
/// the insertion moved them and however many callers it rewrote.
#[test]
fn an_inserted_function_leaves_the_other_symbols_identity_alone() {
    let before = WasmBackend.parse(CODE_MODULE).unwrap();
    let after = WasmBackend
        .parse(CODE_MODULE_WITH_INSERTED_FUNCTION)
        .unwrap();

    let named = |artifact: &ArtifactIr, wanted: &str| {
        artifact
            .symbols
            .iter()
            .find(|symbol| symbol.name.as_deref() == Some(wanted))
            .cloned()
            .unwrap_or_else(|| unreachable!("{wanted} is one of the fixture's functions"))
    };

    // The variant has to actually move the pre-existing functions, or the
    // property below would hold for a reason this test does not establish.
    assert_eq!(after.symbols.len(), before.symbols.len() + 1);
    assert_ne!(
        named(&before, "foo").code,
        named(&after, "foo").code,
        "the insertion must rewrite the call immediate in foo"
    );
    assert_ne!(
        named(&before, "bar").offset,
        named(&after, "bar").offset,
        "the insertion must move bar within the code section"
    );

    for function in ["foo", "bar"] {
        assert_eq!(
            named(&before, function).fingerprint,
            named(&after, function).fingerprint,
            "{function} lost its identity to an index shift"
        );
        // The identity that tells two builds of one symbol apart has to be as
        // index-free as the one that pairs them, or a comparison reports every
        // caller of a shifted function as changed.
        assert_eq!(
            named(&before, function).body_fingerprint,
            named(&after, function).body_fingerprint,
            "{function} lost its body identity to an index shift"
        );
        assert!(named(&after, function).body_fingerprint.is_some());
    }

    let report = ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &before,
        None,
        std::path::Path::new("after.wasm"),
        &after,
        None,
    );
    assert_eq!(
        report
            .symbol_deltas
            .iter()
            .map(|delta| (delta.kind, delta.name.as_deref()))
            .collect::<Vec<_>>(),
        vec![("added", Some("mid"))]
    );
    assert_eq!(report.symbol_changes.added, 1);
    assert_eq!(report.symbol_changes.removed, 0);
    assert_eq!(report.symbol_changes.modified_named_symbols, 0);
}

/// A module with two named functions, each body supplied whole including its
/// local declarations.
///
/// The module is assembled here rather than written out as bytes so that two
/// builds of it can differ in one instruction and in nothing else.
fn two_named_function_module(bodies: [&[u8]; 2]) -> Vec<u8> {
    let mut module = vec![
        0, 97, 115, 109, 1, 0, 0, 0, // magic and version
        1, 4, 1, 0x60, 0, 0, // one type: [] -> []
        3, 3, 2, 0, 0, // two functions of that type
    ];
    let mut code = vec![2];
    for body in bodies {
        code.push(u8::try_from(body.len()).expect("fixture body fits one byte"));
        code.extend(body);
    }
    module.push(10);
    module.push(u8::try_from(code.len()).expect("fixture code section fits one byte"));
    module.extend(code);
    // A `name` custom section calling function 0 `narrowed` and function 1
    // `retuned`, so both changes below belong to a name a reader can act on.
    let mut names = vec![2, 0, 8];
    names.extend(b"narrowed");
    names.extend([1, 7]);
    names.extend(b"retuned");
    let mut custom = vec![4, b'n', b'a', b'm', b'e', 1];
    custom.push(u8::try_from(names.len()).expect("fixture name subsection fits one byte"));
    custom.extend(names);
    module.push(0);
    module.push(u8::try_from(custom.len()).expect("fixture custom section fits one byte"));
    module.extend(custom);
    module
}

/// Normalization drops immediates on purpose, so a build that only rewrote a
/// constant leaves both functions under the identity they already had. That is
/// the characteristic effect of an optimizing build, and a comparison that
/// pairs on identity alone reports it as no difference at all.
///
/// Both modules go through the parser, so what is compared is what the backend
/// establishes rather than a pair of symbols written to agree.
#[test]
fn a_changed_immediate_is_reported_even_though_it_normalizes_away() {
    // narrowed: i32.const 1000000 becomes i32.const 0, which is two bytes
    // shorter. retuned: i32.const 1 becomes i32.const 2, same width.
    let before = WasmBackend
        .parse(&two_named_function_module([
            &[0, 0x41, 0xc0, 0x84, 0x3d, 0x1a, 0x0b],
            &[0, 0x41, 0x01, 0x1a, 0x0b],
        ]))
        .unwrap();
    let after = WasmBackend
        .parse(&two_named_function_module([
            &[0, 0x41, 0x00, 0x1a, 0x0b],
            &[0, 0x41, 0x02, 0x1a, 0x0b],
        ]))
        .unwrap();

    let named = |artifact: &ArtifactIr, wanted: &str| {
        artifact
            .symbols
            .iter()
            .find(|symbol| symbol.name.as_deref() == Some(wanted))
            .cloned()
            .unwrap_or_else(|| unreachable!("{wanted} is one of the fixture's functions"))
    };
    // The fixture is only about immediates if normalization really erased the
    // difference, which is what makes the identities equal on both sides.
    for function in ["narrowed", "retuned"] {
        assert_eq!(
            named(&before, function).fingerprint,
            named(&after, function).fingerprint,
            "{function} must normalize to the identity it already had"
        );
        assert_ne!(
            named(&before, function).body_fingerprint,
            named(&after, function).body_fingerprint,
            "{function} must differ in the bytes normalization dropped"
        );
    }
    assert_eq!(named(&before, "narrowed").size, 7);
    assert_eq!(named(&after, "narrowed").size, 5);
    assert_eq!(
        named(&before, "retuned").size,
        named(&after, "retuned").size
    );

    let report = ArtifactComparisonReport::new(
        std::path::Path::new("before.wasm"),
        &before,
        None,
        std::path::Path::new("after.wasm"),
        &after,
        None,
    );

    assert_eq!(
        report
            .symbol_deltas
            .iter()
            .map(|delta| (delta.kind, delta.name.as_deref(), delta.size_delta_bytes))
            .collect::<Vec<_>>(),
        vec![
            ("resized", Some("narrowed"), -2),
            ("modified", Some("retuned"), 0),
        ]
    );
    assert_eq!(report.symbol_changes.modified_named_symbols, 2);
    assert_eq!(report.symbol_changes.added, 0);
    assert_eq!(report.symbol_changes.removed, 0);

    let json = serde_json::to_value(&report).unwrap();
    assert_valid_schema(
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-comparison-report-v2.schema.json",
        ARTIFACT_COMPARISON_REPORT_JSON_SCHEMA,
        &json,
    );
    let mut text = Vec::new();
    render_compare_text(&report, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("resized narrowed"), "{text}");
    assert!(text.contains("-2 bytes"), "{text}");
    assert!(text.contains("modified retuned"), "{text}");

    let mut csv = Vec::new();
    render_compare_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(
        csv.lines()
            .any(|row| row.starts_with("symbol-delta,") && row.contains(",resized,")),
        "{csv}"
    );
    assert!(
        csv.lines()
            .any(|row| row.starts_with("symbol-delta,") && row.contains(",modified,")),
        "{csv}"
    );
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
            body_fingerprint: None,
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
        body_fingerprint: None,
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
        "https://github.com/libraz/codehelion/blob/main/crates/codehelion-cli/schema/artifact-comparison-report-v2.schema.json",
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
    let mut csv = Vec::new();
    render_compare_csv(&report, &mut csv).unwrap();
    assert!(
        String::from_utf8(csv)
            .unwrap()
            .contains("build-variant-warning")
    );
    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json["build_variant_warning"]
            .as_str()
            .is_some_and(|warning| warning.contains("no build variants"))
    );
}

/// The first question a size difference raises is whether code or data grew,
/// and a comparison holds both artifacts already.
#[test]
fn a_comparison_attributes_its_difference_to_code_or_data() {
    let mut before = resolved_call_graph_artifact();
    before.sections[0].size = 48;
    let mut after = before.clone();
    after.sections[0].size = 32;
    after.data_segments[0].bytes = b"0123456789abcdefghij".to_vec();
    let report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &before,
        None,
        FilePath::new("after.wasm"),
        &after,
        None,
    );

    assert_eq!(report.before.code_section_bytes, 48);
    assert_eq!(report.after.code_section_bytes, 32);
    assert_eq!(report.code_section_delta_bytes, -16);
    assert_eq!(report.before.data_segment_bytes, 16);
    assert_eq!(report.after.data_segment_bytes, 20);
    assert_eq!(report.data_segment_delta_bytes, 4);

    let text = rendered_compare_text(&report);
    assert!(
        text.contains("code section bytes: 48 before, 32 after, -16 bytes (smaller)"),
        "{text}"
    );
    assert!(
        text.contains("data segment bytes: 16 before, 20 after, +4 bytes (larger)"),
        "{text}"
    );

    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["before"]["code_section_bytes"], 48);
    assert_eq!(json["after"]["data_segment_bytes"], 20);
    assert_eq!(json["code_section_delta_bytes"], -16);
    assert_eq!(json["data_segment_delta_bytes"], 4);

    let summary = compare_csv_records(&report)
        .into_iter()
        .find(|record| record[compare_column::RECORD_TYPE] == "summary")
        .expect("one summary record");
    assert_eq!(summary[compare_column::BEFORE_CODE_SECTION_BYTES], "48");
    assert_eq!(summary[compare_column::AFTER_CODE_SECTION_BYTES], "32");
    assert_eq!(summary[compare_column::CODE_SECTION_DELTA_BYTES], "-16");
    assert_eq!(summary[compare_column::BEFORE_DATA_SEGMENT_BYTES], "16");
    assert_eq!(summary[compare_column::AFTER_DATA_SEGMENT_BYTES], "20");
    assert_eq!(summary[compare_column::DATA_SEGMENT_DELTA_BYTES], "4");
}

/// A measurement names the saved analysis it was taken against, and says when
/// it refreshed a measurement that was already on file. Re-measuring is the
/// first thing anyone does when a number looks wrong, and a report that keeps
/// silent about which of several analyses it used cannot be reproduced.
#[test]
fn a_calibration_names_the_analysis_it_used_and_whether_it_was_already_recorded() {
    let artifact = resolved_call_graph_artifact();
    let mut report = ArtifactComparisonReport::new(
        FilePath::new("before.wasm"),
        &artifact,
        None,
        FilePath::new("after.wasm"),
        &artifact,
        None,
    );
    report.calibration = Some(CalibrationReport {
        source_run: 7,
        clone_group_fingerprint: fingerprint_hex([7; 16]),
        estimated_refactor_savings_bytes: EstimatedRefactorSavingsBytes(4),
        verified_savings_bytes: VerifiedSavingsBytes(6),
        absolute_error_bytes: 2,
        relative_error: Some(0.5),
        artifact_analysis_id: 12,
        matching_analyses: 2,
        already_recorded: true,
    });

    let text = rendered_compare_text(&report);
    assert!(
        text.contains("measured against analysis 12 of 2 matching, already recorded"),
        "{text}"
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["calibration"]["artifact_analysis_id"], 12);
    assert_eq!(json["calibration"]["matching_analyses"], 2);
    assert_eq!(json["calibration"]["already_recorded"], true);
    let record = compare_csv_records(&report)
        .into_iter()
        .find(|record| record[compare_column::RECORD_TYPE] == "calibration")
        .expect("one calibration record");
    assert_eq!(record[compare_column::ARTIFACT_ANALYSIS_ID], "12");
    assert_eq!(record[compare_column::MATCHING_ANALYSES], "2");
    assert_eq!(
        record[compare_column::CALIBRATION_RECORD],
        "already recorded"
    );
}
