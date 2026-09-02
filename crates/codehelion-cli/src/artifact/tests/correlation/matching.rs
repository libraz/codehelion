//! Fallback matching: name candidates, path spelling, and fragment extents.

use super::*;

#[test]
fn conflicting_generic_origin_and_name_candidates_remain_ambiguous() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("crate::render<u8>".to_owned()),
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
    let units = [
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/generic.rs".to_owned(),
            name: Some("generic_origin".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([6; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/named.rs".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        },
    ];
    let instantiations = [SourceInstantiation {
        definition: "crate::render".to_owned(),
        artifact_match_key: None,
        instantiation_key: "crate::render<u8>".to_owned(),
        file_path: "/work/src/generic.rs".to_owned(),
        line: 2,
        definition_end_line: None,
        translation_unit: "src/lib.rs".to_owned(),
    }];
    let resolved_symbols = [SourceResolvedSymbol {
        name: "crate::render".to_owned(),
        file_path: "/work/src/named.rs".to_owned(),
        line: 2,
        macro_definition: None,
    }];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &instantiations,
        &resolved_symbols,
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 2);
    assert_eq!(
        rows.mappings
            .iter()
            .map(|mapping| mapping.source_fingerprint)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([[3; 16], [6; 16]])
    );
    assert!(rows.mappings.iter().all(|mapping| {
        mapping.evidence.has_conflict
            && mapping.evidence.confidence()
                == Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Ambiguous)
    }));
}

/// One symbol assembled from two source files: twenty lines of the file the
/// fragment lives in and ten lines inlined from elsewhere.
fn symbol_assembled_from_two_files() -> codehelion_artifact::ArtifactSymbol {
    let frame = |source: &str, line: u32| codehelion_artifact::ArtifactInlineFrame {
        evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
        source: source.to_owned(),
        line: Some(line),
        column: None,
    };
    codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"assembled"),
        name: Some("assembled".to_owned()),
        exported: false,
        section: Some(1),
        offset: 0,
        size: 3_000,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: (1..=20)
            .map(|line| frame("/work/src/main.cpp", line))
            .chain((100..=109).map(|line| frame("/work/src/helper.cpp", line)))
            .collect(),
    }
}

/// The fragment covering every line the symbol contributes in `src/main.cpp`.
fn fragment_over_the_whole_file_extent() -> SourceFragmentIdentity {
    SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        file_path: "src/main.cpp".to_owned(),
        start_line: Some(1),
        end_line: Some(20),
    }
}

fn direct_location_mapping(
    symbol: &codehelion_artifact::ArtifactSymbol,
    fragment: &SourceFragmentIdentity,
) -> ArtifactAnalysisMapping {
    ArtifactAnalysisMapping {
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
    }
}

/// A fragment holds none of the lines its symbol picked up from another file,
/// so those lines count in the divisor and the share stays an estimate.
#[test]
fn lines_inlined_from_another_file_count_toward_the_symbol_extent() {
    let symbol = symbol_assembled_from_two_files();
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"assembled");
    artifact.symbols.push(symbol.clone());
    let fragment = fragment_over_the_whole_file_extent();
    let mut mappings = vec![direct_location_mapping(&symbol, &fragment)];

    assign_unambiguous_fragment_bytes(
        &artifact,
        FilePath::new("/work"),
        &[fragment],
        &mut mappings,
    );

    assert_eq!(mappings[0].attributed_bytes, Some(2_000));
    assert_eq!(
        mappings[0].evidence.attribution_is_whole_symbol(),
        Some(false)
    );
    assert!(
        mappings[0]
            .evidence
            .facts
            .contains(&MappingEvidenceFact::ProportionalSymbolAttribution {
                covered_lines: 20,
                symbol_lines: 30,
            }),
        "{:?}",
        mappings[0].evidence.facts
    );
}

/// The same fragment over a symbol built from its file alone: every line the
/// symbol contributes is inside the fragment, so the whole symbol is observed.
#[test]
fn a_symbol_confined_to_the_fragments_file_is_attributed_whole() {
    let mut symbol = symbol_assembled_from_two_files();
    symbol
        .inline_stack
        .retain(|frame| frame.source == "/work/src/main.cpp");
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"assembled");
    artifact.symbols.push(symbol.clone());
    let fragment = fragment_over_the_whole_file_extent();
    let mut mappings = vec![direct_location_mapping(&symbol, &fragment)];

    assign_unambiguous_fragment_bytes(
        &artifact,
        FilePath::new("/work"),
        &[fragment],
        &mut mappings,
    );

    assert_eq!(mappings[0].attributed_bytes, Some(3_000));
    assert_eq!(
        mappings[0].evidence.attribution_is_whole_symbol(),
        Some(true)
    );
}

#[test]
fn same_named_units_remain_ambiguous_name_candidates() {
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
    let units = [
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/left.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([6; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/right.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(30),
            end_line: Some(40),
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

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 2);
    assert!(rows.mappings.iter().all(|mapping| {
        mapping.evidence.confidence()
            == Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Ambiguous)
            && mapping.evidence.candidate_count == 2
    }));

    let repeated = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );
    assert_eq!(rows, repeated);
    assert_eq!(
        serde_json::to_vec(&ArtifactCorrelationReport::from_rows(7, &artifact, &rows)).unwrap(),
        serde_json::to_vec(&ArtifactCorrelationReport::from_rows(
            7, &artifact, &repeated
        ))
        .unwrap()
    );
}

#[test]
fn equal_content_declarations_each_receive_their_own_name_mapping() {
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
    let units = [
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/left.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/right.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(30),
            end_line: Some(40),
        },
    ];
    let resolved_symbols = [
        SourceResolvedSymbol {
            name: "project::render".to_owned(),
            file_path: "/work/src/left.cpp".to_owned(),
            line: 12,
            macro_definition: None,
        },
        SourceResolvedSymbol {
            name: "project::render".to_owned(),
            file_path: "/work/src/right.cpp".to_owned(),
            line: 32,
            macro_definition: None,
        },
    ];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[],
        &resolved_symbols,
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert_eq!(rows.mappings.len(), 2);
    assert_eq!(
        rows.mappings
            .iter()
            .map(|mapping| mapping.source_instance_fingerprint)
            .collect::<BTreeSet<_>>(),
        units
            .iter()
            .map(source_unit_instance_fingerprint)
            .collect::<BTreeSet<_>>(),
        "every equal-content occurrence keeps its own correspondence"
    );
    assert!(rows.mappings.iter().all(|mapping| {
        mapping.evidence.candidate_count == 2
            && mapping.evidence.confidence()
                == Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Ambiguous)
    }));
    assert!(rows.unmapped_sources.is_empty());
}

/// Debug information written on Windows spells a file with `\`, while the scan
/// records it with `/`. Every path comparison in the correlation module has to
/// reach the same verdict about that pair, or a symbol is placed by one
/// question and dropped as outside the scanned tree by the next.
#[test]
fn one_file_spelled_with_either_separator_correlates_the_same_way() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::PeCoff, b"windows-paths");
    artifact.symbols.push(codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"render"),
        name: Some("render".to_owned()),
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
            source: r"C:\work\src\render.cpp".to_owned(),
            line: Some(12),
            column: None,
        }],
    });
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/render.cpp".to_owned(),
        name: Some("render".to_owned()),
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
        file_path: "src/render.cpp".to_owned(),
        start_line: Some(11),
        end_line: Some(13),
    }];
    let instantiations = [SourceInstantiation {
        definition: "render".to_owned(),
        artifact_match_key: None,
        instantiation_key: "render<int>".to_owned(),
        file_path: r"C:\work\src\render.cpp".to_owned(),
        line: 10,
        definition_end_line: Some(20),
        translation_unit: "src/render.cpp".to_owned(),
    }];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("C:/work"),
        &units,
        &fragments,
        &instantiations,
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert!(rows.unmapped_sources.is_empty());
    let kinds: BTreeSet<_> = rows
        .mappings
        .iter()
        .map(|mapping| source_kind_order(mapping.source_kind))
        .collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            source_kind_order(ArtifactAnalysisSourceKind::Unit),
            source_kind_order(ArtifactAnalysisSourceKind::Fragment),
        ])
    );
    // The fragment side is fail-closed, so its byte attribution is the proof
    // that the line extent was compared under the same spelling too.
    let fragment = rows
        .mappings
        .iter()
        .find(|mapping| mapping.source_kind == ArtifactAnalysisSourceKind::Fragment)
        .expect("the fragment mapping was established");
    assert_eq!(fragment.attributed_bytes, Some(8));
    // The compiler-reported generic definition covers the unit through the
    // same rule, whichever separator its anchor arrived with.
    assert!(source_template_definition_contains_unit(
        &instantiations[0],
        FilePath::new("C:/work"),
        &units[0],
    ));
    assert!(source_generic_unit_matches(
        r"C:\work\src\render.cpp",
        Some(9),
        FilePath::new("C:/work"),
        &units[0],
    ));
    assert!(linker_object_matches_source(
        r"build\src\render.cpp.o",
        "src/render.cpp",
    ));
}
