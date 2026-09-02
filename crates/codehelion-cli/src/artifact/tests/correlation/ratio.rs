//! Coverage counts and the reasons an unmapped side reports.

use super::*;

#[test]
fn correlation_report_keeps_unmapped_bytes_and_reasons_visible() {
    let first = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("one".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 5,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let second = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"two"),
        name: Some("two".to_owned()),
        exported: false,
        section: Some(1),
        offset: 5,
        size: 7,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols = vec![first.clone(), second.clone()];
    let rows = CorrelationRows {
        mappings: Vec::new(),
        unmapped_symbols: vec![
            ArtifactAnalysisUnmappedSymbol {
                artifact_symbol_fingerprint: first.fingerprint.as_bytes(),
                reason: ArtifactAnalysisUnmappedReason::DebugInfoMissing,
            },
            ArtifactAnalysisUnmappedSymbol {
                artifact_symbol_fingerprint: second.fingerprint.as_bytes(),
                reason: ArtifactAnalysisUnmappedReason::OutsideSourceScope,
            },
        ],
        unmapped_sources: Vec::new(),
        clone_fragments: Vec::new(),
    };
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            11, &artifact, &rows,
        )));

    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"unmapped_symbol_bytes\":12"));
    assert!(json.contains("\"debug_info_missing\":1"));
    assert!(json.contains("\"outside_source_scope\":1"));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("2 unmapped symbols (12 bytes)"));
    assert!(text.contains("unmapped symbol reasons:"));
    assert!(text.contains("debug_info_missing: 1"));
    assert!(text.contains("outside_source_scope: 1"));
}

#[test]
fn symbol_coverage_counts_one_population() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"duplicate-symbols");
    artifact.symbols = vec![
        duplicated_symbol(0),
        duplicated_symbol(8),
        codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"alone"),
            name: Some("alone".to_owned()),
            exported: false,
            section: Some(1),
            offset: 16,
            size: 5,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            body_fingerprint: None,
            inline_stack: Vec::new(),
        },
        codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"known"),
            name: Some("known".to_owned()),
            exported: false,
            section: Some(1),
            offset: 21,
            size: 4,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            body_fingerprint: None,
            inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "/work/src/known.cpp".to_owned(),
                line: Some(4),
                column: None,
            }],
        },
    ];
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/known.cpp".to_owned(),
        name: Some("known".to_owned()),
        start_line: Some(1),
        end_line: Some(9),
    }];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );
    let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);

    // The two content-identical entries are one persisted unmapped identity
    // and two entries of the binary; coverage reports the entries.
    assert_eq!(rows.unmapped_symbols.len(), 2);
    assert_eq!(correlation.artifact_symbols, 4);
    assert_eq!(
        correlation.mapped_symbols + correlation.unmapped_symbols,
        correlation.artifact_symbols
    );
    assert_eq!(correlation.mapped_symbols, 1);
    assert_eq!(correlation.unmapped_symbols, 3);
    assert_eq!(correlation.mapped_symbol_bytes, 4);
    assert_eq!(correlation.unmapped_symbol_bytes, 21);
    assert_eq!(
        correlation.unmapped_symbol_reasons,
        BTreeMap::from([
            ("debug_info_missing".to_owned(), 1),
            ("outside_source_scope".to_owned(), 2),
        ])
    );
}
