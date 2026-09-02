use super::*;
use codehelion_store::artifact::ArtifactAnalysisUnmappedSource;
use codehelion_store::query::SourceResolvedSymbol;

#[test]
fn clang_template_display_names_match_only_demangled_function_templates() {
    assert_eq!(
        normalized_clang_template_display_name("clang-display-v1:templates::twice(int)"),
        normalized_clang_template_display_name("int templates::twice<int>(int)")
    );
    assert_eq!(
        normalized_clang_template_display_name("clang-display-v1:templates::twice(long)"),
        normalized_clang_template_display_name("long templates::twice<long>(long)")
    );
    assert_ne!(
        normalized_clang_template_display_name("clang-display-v1:templates::twice(int)"),
        normalized_clang_template_display_name("long templates::twice<long>(long)")
    );
    assert_ne!(
        normalized_clang_template_display_name("clang-display-v1:templates::twice<>(long)"),
        normalized_clang_template_display_name("int templates::twice<int>(int)")
    );
    assert_eq!(
        normalized_clang_template_display_name("templates::ordinary(int)"),
        None
    );
    assert_eq!(
        normalized_clang_template_display_name("templates::Buffer<int, 4>"),
        None
    );
    assert_eq!(
        normalized_clang_template_owner_name("clang-display-v1:templates::Buffer<int, 4>"),
        normalized_clang_template_owner_name(
            "int templates::Buffer<int, 4ul>::at(unsigned long) const"
        )
    );
    assert_eq!(
        normalized_clang_template_owner_name("clang-display-v1:templates::Buffer<int, 4>"),
        normalized_clang_template_owner_name(
            "int templates::Buffer<int, (unsigned long)4>::at(unsigned long) const"
        )
    );
    assert_ne!(
        normalized_clang_template_owner_name("clang-display-v1:templates::Buffer<int, 4>"),
        normalized_clang_template_owner_name(
            "int templates::Buffer<int, 8ul>::at(unsigned long) const"
        )
    );
    assert_eq!(
        normalized_clang_template_owner_name("clang-display-v1:templates::twice<>(int)"),
        None
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps the source-run boundary and all rejected candidates explicit"
)]
fn dwarf_locations_map_only_units_in_the_explicit_source_run() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("entry".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
            evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
            source: "/work/src/main.cpp".to_owned(),
            line: Some(12),
            column: Some(3),
        }],
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(symbol.clone());
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/main.cpp".to_owned(),
        name: Some("entry".to_owned()),
        start_line: Some(10),
        end_line: Some(20),
    }];
    let fragments = [SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        file_path: "src/main.cpp".to_owned(),
        start_line: Some(11),
        end_line: Some(13),
    }];
    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert_eq!(rows.mappings.len(), 2);
    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(
        rows.mappings[0].artifact_symbol_fingerprint,
        symbol.fingerprint.as_bytes()
    );
    assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
    assert_eq!(
        rows.mappings[0].source_build_variant_fingerprint.as_bytes(),
        [4; 16]
    );
    assert_eq!(
        rows.mappings[0].build_variant_fingerprint.as_bytes(),
        [5; 16]
    );
    assert_eq!(
        rows.mappings[0].evidence.confidence(),
        Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Exact)
    );
    assert_eq!(
        rows.mappings[1].source_kind,
        ArtifactAnalysisSourceKind::Fragment
    );
    assert_eq!(rows.mappings[1].source_fingerprint, [6; 16]);
    assert_eq!(rows.mappings[1].attributed_bytes, Some(8));
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, Some(10), None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            7, &artifact, &rows,
        )));
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"schema_version\":\"artifact-report-v2\""));
    assert!(json.contains("\"source_run\":7"));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains(
        "source correlation: scan 7: 2 mappings, 1/1 mapped symbols (100.0%), 8 / 8 mapped symbol bytes (100.0%), 0 unmapped symbols (0 bytes)"
    ));
    assert!(text.contains("source identities: 2, 0 without artifact evidence"));
    let mut csv_out = Vec::new();
    render_csv(&report, &mut csv_out).unwrap();
    let csv = String::from_utf8(csv_out).unwrap();
    assert!(csv.contains("source_run,mappings,mapped_symbols,unmapped_symbols"));
    let mut rows = csv.lines();
    let header: Vec<_> = rows.next().unwrap().split(',').collect();
    let summary: Vec<_> = rows.next().unwrap().split(',').collect();
    for (field, expected) in [
        ("source_run", "7"),
        ("mappings", "2"),
        ("mapped_symbols", "1"),
        ("unmapped_symbols", "0"),
    ] {
        let index = header.iter().position(|value| *value == field).unwrap();
        assert_eq!(summary[index], expected, "unexpected {field} value");
    }
}

#[test]
fn partial_fragment_attribution_is_proportional_and_not_exact() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"partial-attribution");
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"large"),
        name: Some("large_function".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8_000,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: (1..=400)
            .map(|line| codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "/work/src/main.cpp".to_owned(),
                line: Some(line),
                column: None,
            })
            .collect(),
    };
    artifact.symbols.push(symbol.clone());
    let fragment = SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        file_path: "src/main.cpp".to_owned(),
        start_line: Some(101),
        end_line: Some(110),
    };
    let mut mappings = vec![ArtifactAnalysisMapping {
        schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
        artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
        source_kind: ArtifactAnalysisSourceKind::Fragment,
        source_fingerprint: *fragment.fingerprint.as_bytes(),
        source_instance_fingerprint: *fragment.finding_id.as_bytes(),
        source_build_variant_fingerprint: fragment.build_variant_fingerprint,
        evidence: MappingEvidence::new(
            vec![MappingEvidenceFact::Dwarf {
                source_path: "/work/src/main.cpp".to_owned(),
            }],
            1,
            false,
        ),
        attributed_bytes: None,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([5; 16]),
    }];

    assign_unambiguous_fragment_bytes(
        &artifact,
        FilePath::new("/work"),
        &[fragment],
        &mut mappings,
    );

    assert_eq!(mappings[0].attributed_bytes, Some(200));
    assert_eq!(
        mappings[0].evidence.attribution_is_whole_symbol(),
        Some(false)
    );
    assert_eq!(
        mappings[0].evidence.confidence(),
        Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
    );
}

#[test]
fn pdb_location_maps_with_pdb_evidence() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "symbol",
            b"pdb-location",
        ),
        name: Some("entry".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
            evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Pdb,
            source: "/work/src/main.cpp".to_owned(),
            line: Some(12),
            column: Some(3),
        }],
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::PeCoff, b"fixture");
    artifact.symbols.push(symbol);
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/main.cpp".to_owned(),
        name: Some("entry".to_owned()),
        start_line: Some(10),
        end_line: Some(20),
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

    assert_eq!(rows.mappings.len(), 1);
    assert_eq!(
        rows.mappings[0].evidence.facts,
        vec![MappingEvidenceFact::Pdb {
            source_path: "/work/src/main.cpp".to_owned(),
        }]
    );
}

#[test]
fn dwarf_frame_without_line_does_not_map_clone_fragments() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "symbol",
            b"missing-line",
        ),
        name: Some("entry".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
            evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
            source: "/work/src/main.cpp".to_owned(),
            line: None,
            column: None,
        }],
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(symbol);
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/main.cpp".to_owned(),
        name: Some("entry".to_owned()),
        start_line: Some(1),
        end_line: Some(40),
    }];
    let fragments = [
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([6; 16]),
            finding_id: FindingId::from_bytes([16; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            file_path: "src/main.cpp".to_owned(),
            start_line: Some(10),
            end_line: Some(13),
        },
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([7; 16]),
            finding_id: FindingId::from_bytes([18; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
            is_canonical: true,
            clone_confidence: 1.0,
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            file_path: "src/main.cpp".to_owned(),
            start_line: Some(20),
            end_line: Some(23),
        },
    ];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert_eq!(rows.mappings.len(), 1);
    assert_eq!(
        rows.mappings[0].source_kind,
        ArtifactAnalysisSourceKind::Unit
    );
    assert!(
        rows.mappings
            .iter()
            .all(|mapping| mapping.source_kind != ArtifactAnalysisSourceKind::Fragment)
    );
    assert_eq!(
        rows.unmapped_sources
            .iter()
            .filter(|source| source.source_kind == ArtifactAnalysisSourceKind::Fragment)
            .map(|source| source.source_instance_fingerprint)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([[16; 16], [18; 16]])
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the fixture keeps every multi-origin assertion together"
)]
fn inline_stack_retains_every_source_origin_without_double_counting_symbol_bytes() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"inlined"),
        name: Some("combined".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 12,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: vec![
            codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "/work/src/a.cpp".to_owned(),
                line: Some(10),
                column: None,
            },
            codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: "/work/src/b.cpp".to_owned(),
                line: Some(20),
                column: None,
            },
        ],
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(symbol);
    let units = [
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([1; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/a.cpp".to_owned(),
            name: Some("a".to_owned()),
            start_line: Some(1),
            end_line: Some(15),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([2; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/b.cpp".to_owned(),
            name: Some("b".to_owned()),
            start_line: Some(16),
            end_line: Some(25),
        },
    ];
    let fragments = [
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([5; 16]),
            finding_id: FindingId::from_bytes([6; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            file_path: "src/a.cpp".to_owned(),
            start_line: Some(9),
            end_line: Some(11),
        },
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([8; 16]),
            finding_id: FindingId::from_bytes([9; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            is_canonical: true,
            clone_confidence: 1.0,
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            file_path: "src/b.cpp".to_owned(),
            start_line: Some(19),
            end_line: Some(21),
        },
    ];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([10; 16]),
    );

    assert_eq!(rows.mappings.len(), 4);
    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(
        rows.mappings
            .iter()
            .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Unit)
            .map(|mapping| mapping.source_fingerprint)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([[1; 16], [2; 16]])
    );
    assert_eq!(
        rows.mappings
            .iter()
            .filter(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Fragment)
            .map(|mapping| mapping.source_instance_fingerprint)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([[6; 16], [9; 16]])
    );
    assert!(
        rows.mappings
            .iter()
            .all(|mapping| mapping.attributed_bytes.is_none())
    );
}

#[test]
fn source_findings_without_artifact_evidence_are_explicitly_unmapped() {
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/unmatched.cpp".to_owned(),
        name: Some("unmatched".to_owned()),
        start_line: Some(1),
        end_line: Some(2),
    }];
    let fragments = [SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        file_path: "src/unmatched.cpp".to_owned(),
        start_line: Some(1),
        end_line: Some(2),
    }];
    let unit_instance = source_unit_instance_fingerprint(&units[0]);

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.mappings.is_empty());
    assert_eq!(
        rows.unmapped_sources,
        vec![
            ArtifactAnalysisUnmappedSource {
                source_kind: ArtifactAnalysisSourceKind::Unit,
                source_fingerprint: [3; 16],
                source_instance_fingerprint: unit_instance,
                source_build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
                reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
            },
            ArtifactAnalysisUnmappedSource {
                source_kind: ArtifactAnalysisSourceKind::Fragment,
                source_fingerprint: [6; 16],
                source_instance_fingerprint: [16; 16],
                source_build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
                reason: ArtifactAnalysisUnmappedSourceReason::NoArtifactEvidence,
            },
        ]
    );
    let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
    assert_eq!(correlation.source_entities, 2);
    assert_eq!(correlation.unmapped_sources, 2);
    assert_eq!(
        correlation.unmapped_source_reasons,
        BTreeMap::from([("no_artifact_evidence".to_owned(), 2)])
    );
}

#[test]
fn equal_content_source_units_keep_distinct_unmapped_occurrences() {
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let units = [
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/left.cpp".to_owned(),
            name: Some("duplicate".to_owned()),
            start_line: Some(1),
            end_line: Some(3),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/right.cpp".to_owned(),
            name: Some("duplicate".to_owned()),
            start_line: Some(1),
            end_line: Some(3),
        },
    ];

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

    assert_eq!(rows.unmapped_sources.len(), 2);
    assert_ne!(
        rows.unmapped_sources[0].source_instance_fingerprint,
        rows.unmapped_sources[1].source_instance_fingerprint
    );
}

#[test]
fn source_unit_instance_identity_ignores_anchors_but_keeps_duplicate_occurrences() {
    let unit = SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/widget.cpp".to_owned(),
        name: Some("render".to_owned()),
        start_line: Some(10),
        end_line: Some(20),
    };
    let shifted = SourceUnitIdentity {
        start_line: Some(110),
        end_line: Some(120),
        ..unit.clone()
    };
    let duplicate = SourceUnitIdentity {
        occurrence_ordinal: 2,
        ..unit.clone()
    };

    assert_eq!(
        source_unit_instance_fingerprint(&unit),
        source_unit_instance_fingerprint(&shifted),
        "reporting anchors are not source-unit identity"
    );
    assert_ne!(
        source_unit_instance_fingerprint(&unit),
        source_unit_instance_fingerprint(&duplicate),
        "the ordinal retains two otherwise identical declarations"
    );
}

#[test]
fn demangled_name_maps_one_named_unit_as_weak_evidence() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("project::Widget::render(int)".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(symbol);
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/widget.cpp".to_owned(),
        name: Some("render".to_owned()),
        start_line: Some(10),
        end_line: Some(20),
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

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 1);
    assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
    assert_eq!(
        rows.mappings[0].evidence.confidence(),
        Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Weak)
    );
    assert_eq!(
        rows.mappings[0].evidence.facts,
        vec![MappingEvidenceFact::SymbolName {
            source_symbol: "render".to_owned(),
            artifact_symbol: "render".to_owned(),
        }]
    );
}

#[test]
fn macro_definition_anchor_beats_an_unrelated_unit_label() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("project::render()".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(symbol);
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/widget.cpp".to_owned(),
        name: Some("unrelated".to_owned()),
        start_line: Some(10),
        end_line: Some(20),
    }];
    let resolved = [SourceResolvedSymbol {
        name: "project::render".to_owned(),
        file_path: "/work/src/widget.cpp".to_owned(),
        line: 12,
        macro_definition: Some(codehelion_store::query::SourceMacroDefinition {
            file_path: "/work/src/widget.cpp".to_owned(),
            line: 12,
        }),
    }];
    let fragments = [SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        file_path: "src/widget.cpp".to_owned(),
        start_line: Some(11),
        end_line: Some(13),
    }];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &[],
        &resolved,
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 2);
    assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
    assert_eq!(
        rows.mappings[0].evidence.facts,
        vec![
            MappingEvidenceFact::SymbolName {
                source_symbol: "render".to_owned(),
                artifact_symbol: "render".to_owned(),
            },
            MappingEvidenceFact::MacroOrigin {
                definition_path: "/work/src/widget.cpp".to_owned(),
            },
        ]
    );
    assert_eq!(
        rows.mappings[1].source_kind,
        ArtifactAnalysisSourceKind::Fragment
    );
    assert_eq!(rows.mappings[1].source_fingerprint, [6; 16]);
    let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
    assert_eq!(correlation.macro_origins.len(), 1);
    assert_eq!(correlation.macro_origins[0].artifact_symbols, 1);
    assert_eq!(correlation.macro_origins[0].observed_symbol_bytes, 8);
    assert_eq!(
        correlation.macro_origins[0].definition_paths,
        vec!["/work/src/widget.cpp"]
    );
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(correlation));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("macro origins (observed symbol bytes):")
    );
    let mut csv_output = Vec::new();
    render_csv(&report, &mut csv_output).unwrap();
    assert!(
        String::from_utf8(csv_output)
            .unwrap()
            .contains("macro-origin,fixture.so,elf,macro-origin")
    );
}

#[test]
#[allow(clippy::too_many_lines)] // The fixture keeps both call-graph sides visible.
fn matching_static_calls_add_independent_neighborhood_evidence() {
    let caller = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"caller"),
        name: Some("crate::render()".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let target = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"target"),
        name: Some("crate::escape()".to_owned()),
        exported: false,
        section: Some(1),
        offset: 8,
        size: 4,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols = vec![caller.clone(), target.clone()];
    artifact.calls.push(codehelion_artifact::ArtifactCall {
        caller: caller.fingerprint,
        target: Some(target.fingerprint),
        unresolved: None,
    });
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/render.rs".to_owned(),
        name: Some("render".to_owned()),
        start_line: Some(1),
        end_line: Some(20),
    }];
    let resolved_symbols = [SourceResolvedSymbol {
        name: "crate::render".to_owned(),
        file_path: "/work/src/render.rs".to_owned(),
        line: 1,
        macro_definition: None,
    }];
    let resolved_calls = [SourceResolvedCall {
        target_name: "crate::escape".to_owned(),
        file_path: "/work/src/render.rs".to_owned(),
        line: 3,
    }];
    let fragments = [SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        file_path: "src/render.rs".to_owned(),
        start_line: Some(1),
        end_line: Some(10),
    }];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &[],
        &resolved_symbols,
        &resolved_calls,
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    let mapping = rows
        .mappings
        .iter()
        .find(|mapping| mapping.artifact_symbol_fingerprint == caller.fingerprint.as_bytes())
        .unwrap();
    assert_eq!(
        mapping.evidence.facts,
        vec![
            MappingEvidenceFact::SymbolName {
                source_symbol: "render".to_owned(),
                artifact_symbol: "render".to_owned(),
            },
            MappingEvidenceFact::CallGraphNeighborhood,
        ]
    );
    assert_eq!(
        mapping.evidence.confidence(),
        Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
    );
    let fragment_mapping = rows
        .mappings
        .iter()
        .find(|mapping| {
            mapping.artifact_symbol_fingerprint == caller.fingerprint.as_bytes()
                && mapping.source_kind == ArtifactAnalysisSourceKind::Fragment
        })
        .unwrap();
    assert_eq!(
        fragment_mapping.evidence.confidence(),
        Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
    );
}
