use super::*;

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the regression keeps source-unit, fragment, and translation-unit assertions together"
)]
fn exact_generic_instantiation_key_maps_the_definition_origin() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("crate::Buffer::push::<String>".to_owned()),
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
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/generic.rs".to_owned(),
        name: Some("unrelated".to_owned()),
        start_line: Some(10),
        end_line: Some(20),
    }];
    let instantiations = [
        SourceInstantiation {
            definition: "crate::Buffer::push".to_owned(),
            artifact_match_key: None,
            instantiation_key: "crate::Buffer::push<String>".to_owned(),
            file_path: "/work/src/generic.rs".to_owned(),
            line: 12,
            definition_end_line: None,
            translation_unit: "src/one.rs".to_owned(),
        },
        SourceInstantiation {
            definition: "crate::Buffer::push".to_owned(),
            artifact_match_key: None,
            instantiation_key: "crate::Buffer::push<String>".to_owned(),
            file_path: "/work/src/generic.rs".to_owned(),
            line: 12,
            definition_end_line: None,
            translation_unit: "src/two.rs".to_owned(),
        },
    ];
    let fragments = [SourceFragmentIdentity {
        fingerprint: FragmentFingerprint::from_bytes([6; 16]),
        finding_id: FindingId::from_bytes([16; 16]),
        clone_group_fingerprint: CloneGroupFingerprint::from_bytes([17; 16]),
        is_canonical: false,
        clone_confidence: 1.0,
        build_variant_fingerprint: [4; 16],
        file_path: "src/generic.rs".to_owned(),
        start_line: Some(11),
        end_line: Some(13),
    }];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &fragments,
        &instantiations,
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 2);
    assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
    assert_eq!(
        rows.mappings[0].evidence.facts,
        vec![MappingEvidenceFact::GenericOrigin {
            definition: "crate::Buffer::push".to_owned(),
            instantiation_key: "crate::Buffer::push<String>".to_owned(),
            translation_units: vec!["src/one.rs".to_owned(), "src/two.rs".to_owned()],
        }]
    );
    assert_eq!(
        rows.mappings[1].source_kind,
        ArtifactAnalysisSourceKind::Fragment
    );
    assert_eq!(rows.mappings[1].source_fingerprint, [6; 16]);

    let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
    assert_eq!(correlation.generic_origins.len(), 1);
    assert_eq!(
        correlation.generic_origins[0].origin_fingerprint,
        fingerprint_hex(generic_origin_fingerprint([3; 16], "crate::Buffer::push"))
    );
    assert_eq!(
        correlation.generic_origins[0].definition,
        "crate::Buffer::push"
    );
    assert_eq!(correlation.generic_origins[0].instantiations, 1);
    assert_eq!(correlation.generic_origins[0].translation_units, 2);
    assert_eq!(correlation.generic_origins[0].artifact_symbols, 1);
    assert_eq!(correlation.generic_origins[0].observed_symbol_bytes, 8);
    assert_eq!(
        correlation.generic_origins[0].normalized_instruction_duplicated_bytes,
        0
    );
    assert_eq!(correlation.generic_origins[0].retained_size_sum, None);
    assert_eq!(correlation.generic_origins[0].specializations.len(), 1);
    assert_eq!(
        correlation.generic_origins[0].specializations[0].translation_units,
        2
    );
    assert_eq!(
        correlation.generic_origins[0].specializations[0].instantiation_key,
        "crate::Buffer::push<String>"
    );
    assert_eq!(
        correlation.generic_origins[0].specializations[0].type_arguments,
        vec!["String"]
    );
    let mut text = Vec::new();
    render_text(
        &ArtifactReport::from_ir(std::path::Path::new("fixture.so"), &artifact, None, None)
            .with_correlation(Some(correlation.clone())),
        false,
        &mut text,
    )
    .unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("1 instantiations across 2 translation units")
    );
    assert_eq!(
        correlation.generic_origins[0].specializations[0].observed_symbol_bytes,
        8
    );

    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(correlation));
    let mut csv_output = Vec::new();
    render_csv(&report, &mut csv_output).unwrap();
    let csv_output = String::from_utf8(csv_output).unwrap();
    let mut csv_rows = csv_output.lines();
    let width = csv_rows.next().unwrap().split(',').count();
    assert!(csv_rows.all(|row| row.split(',').count() == width));
    assert!(csv_output.contains(&format!(
        "generic-origin,fixture.so,elf,generic-origin,{},crate::Buffer::push,,8,0",
        fingerprint_hex(generic_origin_fingerprint([3; 16], "crate::Buffer::push"))
    )));
    assert!(csv_output.contains(&format!(
        "generic-specialization,fixture.so,elf,generic-origin,{},crate::Buffer::push<String>,,8",
        fingerprint_hex(generic_origin_fingerprint([3; 16], "crate::Buffer::push"))
    )));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    assert!(
        String::from_utf8(text)
            .unwrap()
            .contains("generic origins (observed symbol bytes):")
    );
}

#[test]
fn generic_origin_maps_one_source_to_each_instantiated_symbol() {
    let first = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"u8"),
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
    let second = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"u16"),
        name: Some("crate::render<u16>".to_owned()),
        offset: 8,
        ..first.clone()
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols = vec![first.clone(), second.clone()];
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/generic.rs".to_owned(),
        name: Some("render".to_owned()),
        start_line: Some(1),
        end_line: Some(10),
    }];
    let instantiations = [
        SourceInstantiation {
            definition: "crate::render".to_owned(),
            artifact_match_key: None,
            instantiation_key: "crate::render<u8>".to_owned(),
            file_path: "/work/src/generic.rs".to_owned(),
            line: 2,
            definition_end_line: None,
            translation_unit: "src/first.rs".to_owned(),
        },
        SourceInstantiation {
            definition: "crate::render".to_owned(),
            artifact_match_key: None,
            instantiation_key: "crate::render<u16>".to_owned(),
            file_path: "/work/src/generic.rs".to_owned(),
            line: 2,
            definition_end_line: None,
            translation_unit: "src/second.rs".to_owned(),
        },
    ];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &instantiations,
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 2);
    assert!(
        rows.mappings
            .iter()
            .all(|mapping| mapping.source_fingerprint == [3; 16])
    );
    assert_eq!(
        rows.mappings
            .iter()
            .map(|mapping| mapping.artifact_symbol_fingerprint)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([first.fingerprint.as_bytes(), second.fingerprint.as_bytes()])
    );
    assert!(rows.mappings.iter().all(|mapping| {
        mapping
            .evidence
            .facts
            .iter()
            .any(|fact| matches!(fact, MappingEvidenceFact::GenericOrigin { .. }))
    }));
}

#[test]
fn clang_template_display_key_maps_only_its_demangled_specialization() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"twice-int"),
        name: Some("int templates::twice<int>(int)".to_owned()),
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
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "include/templates.hpp".to_owned(),
        name: Some("unrelated".to_owned()),
        start_line: Some(1),
        end_line: Some(20),
    }];
    let instantiations = [
        SourceInstantiation {
            definition: "c:@N@templates@FT@twice#t0.0#".to_owned(),
            artifact_match_key: Some("clang-display-v1:templates::twice<>(int)".to_owned()),
            instantiation_key: "clang-usr-v1:c:@N@templates@F@twice<#I>#I#".to_owned(),
            file_path: "/work/include/templates.hpp".to_owned(),
            line: 4,
            definition_end_line: None,
            translation_unit: "src/templates.cpp".to_owned(),
        },
        SourceInstantiation {
            definition: "c:@N@templates@FT@twice#t0.0#".to_owned(),
            artifact_match_key: Some("clang-display-v1:templates::twice<>(long)".to_owned()),
            instantiation_key: "clang-usr-v1:c:@N@templates@F@twice<#L>#L#".to_owned(),
            file_path: "/work/include/templates.hpp".to_owned(),
            line: 4,
            definition_end_line: None,
            translation_unit: "src/templates.cpp".to_owned(),
        },
    ];

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &instantiations,
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 1);
    assert_eq!(rows.mappings[0].source_fingerprint, [3; 16]);
    assert_eq!(
        rows.mappings[0].evidence.facts,
        vec![MappingEvidenceFact::GenericOrigin {
            definition: "c:@N@templates@FT@twice#t0.0#".to_owned(),
            instantiation_key: "clang-usr-v1:c:@N@templates@F@twice<#I>#I#".to_owned(),
            translation_units: vec!["src/templates.cpp".to_owned()],
        }]
    );
}

#[test]
fn clang_template_owner_key_maps_only_its_member_specialization() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "symbol",
            b"buffer-int-four",
        ),
        name: Some("int templates::Buffer<int, 4ul>::at(unsigned long) const".to_owned()),
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
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "include/templates.hpp".to_owned(),
        name: Some("unrelated".to_owned()),
        start_line: Some(10),
        end_line: Some(15),
    }];
    let instantiations = [
        SourceInstantiation {
            definition: "c:@N@templates@S@Buffer>#I#VI4".to_owned(),
            artifact_match_key: Some("clang-display-v1:templates::Buffer<int, 4>".to_owned()),
            instantiation_key: "clang-usr-v1:c:@N@templates@S@Buffer>#I#VI4".to_owned(),
            file_path: "/work/include/templates.hpp".to_owned(),
            line: 8,
            definition_end_line: Some(20),
            translation_unit: "src/templates.cpp".to_owned(),
        },
        SourceInstantiation {
            definition: "c:@N@templates@S@Buffer>#I#VI8".to_owned(),
            artifact_match_key: Some("clang-display-v1:templates::Buffer<int, 8>".to_owned()),
            instantiation_key: "clang-usr-v1:c:@N@templates@S@Buffer>#I#VI8".to_owned(),
            file_path: "/work/include/templates.hpp".to_owned(),
            line: 8,
            definition_end_line: Some(20),
            translation_unit: "src/templates.cpp".to_owned(),
        },
    ];

    let mappings = correlate_generic_origin(
        &symbol,
        &SourceLocationIndex::new(FilePath::new("/work"), &units, &[]),
        &InstantiationIndex::new(&instantiations),
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].source_fingerprint, [3; 16]);
    assert_eq!(
        mappings[0].evidence.facts,
        vec![MappingEvidenceFact::GenericOrigin {
            definition: "c:@N@templates@S@Buffer>#I#VI4".to_owned(),
            instantiation_key: "clang-usr-v1:c:@N@templates@S@Buffer>#I#VI4".to_owned(),
            translation_units: vec!["src/templates.cpp".to_owned()],
        }]
    );
}

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
            build_variant_fingerprint: [4; 16],
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/generic.rs".to_owned(),
            name: Some("generic_origin".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([6; 16]),
            build_variant_fingerprint: [4; 16],
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

#[test]
fn linker_map_recovers_an_unmapped_unit_without_basename_guessing() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: Some("render".to_owned()),
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
    artifact.symbols.push(symbol.clone());
    let units = [
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: [4; 16],
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/render.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([6; 16]),
            build_variant_fingerprint: [4; 16],
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "other/render.cpp".to_owned(),
            name: Some("unrelated".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        },
    ];
    let entries = parse_linker_map(
        " .text.render 0x0000000000001000 0x8 build/CMakeFiles/app.dir/src/render.cpp.o\n\
         0x0000000000001000                render\n",
    );
    assert_eq!(
        entries,
        vec![LinkerMapEntry {
            symbol: "render".to_owned(),
            object_path: "build/CMakeFiles/app.dir/src/render.cpp.o".to_owned(),
        }]
    );
    let mut rows = CorrelationRows {
        unmapped_symbols: vec![ArtifactAnalysisUnmappedSymbol {
            artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
            reason: ArtifactAnalysisUnmappedReason::DebugInfoMissing,
        }],
        ..CorrelationRows::default()
    };

    enrich_linker_map_evidence(
        &artifact,
        &units,
        &entries,
        BuildVariantFingerprint::from_bytes([5; 16]),
        &mut rows,
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 1);
    let mapping = &rows.mappings[0];
    assert_eq!(mapping.source_fingerprint, [3; 16]);
    assert_eq!(mapping.evidence.candidate_count, 1);
    assert_eq!(
        mapping.evidence.facts,
        vec![
            MappingEvidenceFact::SymbolName {
                source_symbol: "render".to_owned(),
                artifact_symbol: "render".to_owned(),
            },
            MappingEvidenceFact::LinkerMap {
                object_path: "build/CMakeFiles/app.dir/src/render.cpp.o".to_owned(),
            },
        ]
    );
    assert_eq!(
        mapping.evidence.confidence(),
        Some(codehelion_store::artifact::ArtifactAnalysisMappingConfidence::Strong)
    );
}

#[test]
fn linker_map_object_paths_must_end_with_the_object_suffix() {
    assert_eq!(
        linker_map_object_path("build/CMakeFiles/app.dir/src/render.cpp.o"),
        Some("build/CMakeFiles/app.dir/src/render.cpp.o".to_owned())
    );
    assert_eq!(
        linker_map_object_path("(build/CMakeFiles/app.dir/src/render.cpp.o)"),
        Some("build/CMakeFiles/app.dir/src/render.cpp.o".to_owned())
    );
    assert_eq!(linker_map_object_path(".text.open"), None);
    assert_eq!(linker_map_object_path("build/object.o.extra"), None);
}

#[test]
fn generic_origin_metrics_keep_normalized_duplicates_separate_from_savings() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    for (name, size) in [("one", 8), ("two", 4)] {
        artifact.symbols.push(codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                name.as_bytes(),
            ),
            name: Some(name.to_owned()),
            exported: false,
            section: Some(1),
            offset: 0,
            size,
            size_inferred: false,
            code: Vec::new(),
            normalized: Some(codehelion_artifact::NormalizedInstructions {
                version: "test-normalization-v1".to_owned(),
                bytes: vec![1, 2, 3],
            }),
            body_fingerprint: None,
            inline_stack: Vec::new(),
        });
    }
    let fingerprints = artifact
        .symbols
        .iter()
        .map(|symbol| symbol.fingerprint.as_bytes())
        .collect();

    assert_eq!(
        generic_origin_metrics(&artifact, &fingerprints, None),
        (12, 4, None)
    );
    artifact.symbols[0].exported = true;
    artifact.capabilities.call_graph = true;
    let retained_sizes = metrics::retained_sizes(&artifact).unwrap();
    assert_eq!(
        generic_origin_metrics(&artifact, &fingerprints, Some(&retained_sizes)),
        (12, 4, Some(8))
    );
}

#[test]
fn generic_type_arguments_keep_nested_specializations_intact() {
    assert_eq!(
        generic_type_arguments("crate::make<Vec<Result<String, Error>>, 4>"),
        vec!["Vec<Result<String, Error>>", "4"]
    );
    assert!(generic_type_arguments("crate::make<>").is_empty());
    assert!(generic_type_arguments("crate::make<String").is_empty());
}

#[test]
fn group_attribution_reports_exact_noncanonical_byte_splits() {
    let fragments = vec![
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([2; 16]),
            finding_id: FindingId::from_bytes([10; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            is_canonical: true,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/one.rs".to_owned(),
            start_line: Some(1),
            end_line: Some(3),
        },
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([2; 16]),
            finding_id: FindingId::from_bytes([11; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/two.rs".to_owned(),
            start_line: Some(1),
            end_line: Some(3),
        },
    ];
    let rows = CorrelationRows {
        mappings: vec![ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: [3; 16],
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: [2; 16],
            source_instance_fingerprint: [11; 16],
            source_build_variant_fingerprint: [4; 16],
            evidence: MappingEvidence::new(
                vec![
                    MappingEvidenceFact::Dwarf {
                        source_path: "src/two.rs".to_owned(),
                    },
                    MappingEvidenceFact::WholeSymbolAttribution,
                ],
                1,
                false,
            ),
            attributed_bytes: Some(9),
            build_variant_fingerprint: [5; 16],
        }],
        unmapped_symbols: Vec::new(),
        unmapped_sources: Vec::new(),
        clone_fragments: fragments,
    };

    assert_eq!(
        clone_group_attributions(&rows)
            .into_iter()
            .map(|attribution| (
                attribution.members,
                attribution.attributed_noncanonical_members,
                attribution.duplicated_bytes,
                attribution.estimated_duplicated_bytes,
            ))
            .collect::<Vec<_>>(),
        vec![(2, 1, Some(9), None)]
    );
    let savings = clone_group_savings(&rows);
    assert_eq!(savings.len(), 1);
    assert_eq!(savings[0].duplicated_bytes, 9);
    assert_eq!(
        savings[0].estimated_refactor_savings_bytes,
        EstimatedRefactorSavingsBytes(9)
    );
    assert_eq!(savings[0].mapping_confidence, EvidenceConfidence::High);
    assert_eq!(savings[0].model_confidence, EvidenceConfidence::Low);
    assert_eq!(savings[0].savings_confidence, EvidenceConfidence::Low);
    assert_eq!(
        serde_json::to_value(&savings[0]).unwrap()["assumptions"][0]["kind"],
        "shared_implementation_retains_copies"
    );
    assert_eq!(
        savings[0].source_build_variant_fingerprint,
        fingerprint_hex([4; 16])
    );
    assert_eq!(
        savings[0].artifact_build_variant_fingerprint,
        fingerprint_hex([5; 16])
    );
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            7, &artifact, &rows,
        )));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("source 04040404040404040404040404040404"));
    assert!(text.contains("artifact 05050505050505050505050505050505"));
    assert!(text.contains("model schema: refactor-savings-model-v1"));
    assert!(text.contains("shared implementation retains 1 copy/copies"));
    assert_clone_group_savings_are_in_json_and_csv(&report);
    assert_eq!(
        serde_json::to_vec(&savings).unwrap(),
        serde_json::to_vec(&clone_group_savings(&rows)).unwrap()
    );
}

/// One group whose only noncanonical member was attributed a line-proportional
/// share of its artifact symbol.
fn line_proportional_rows() -> CorrelationRows {
    let fragments = vec![
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([2; 16]),
            finding_id: FindingId::from_bytes([10; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            is_canonical: true,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/one.rs".to_owned(),
            start_line: Some(1),
            end_line: Some(3),
        },
        SourceFragmentIdentity {
            fingerprint: FragmentFingerprint::from_bytes([2; 16]),
            finding_id: FindingId::from_bytes([11; 16]),
            clone_group_fingerprint: CloneGroupFingerprint::from_bytes([7; 16]),
            is_canonical: false,
            clone_confidence: 1.0,
            build_variant_fingerprint: [4; 16],
            file_path: "src/two.rs".to_owned(),
            start_line: Some(1),
            end_line: Some(3),
        },
    ];
    CorrelationRows {
        mappings: vec![ArtifactAnalysisMapping {
            schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
            artifact_symbol_fingerprint: [3; 16],
            source_kind: ArtifactAnalysisSourceKind::Fragment,
            source_fingerprint: [2; 16],
            source_instance_fingerprint: [11; 16],
            source_build_variant_fingerprint: [4; 16],
            evidence: MappingEvidence::new(
                vec![
                    MappingEvidenceFact::Dwarf {
                        source_path: "src/two.rs".to_owned(),
                    },
                    MappingEvidenceFact::ProportionalSymbolAttribution {
                        covered_lines: 3,
                        symbol_lines: 9,
                    },
                ],
                1,
                false,
            ),
            attributed_bytes: Some(9),
            build_variant_fingerprint: [5; 16],
        }],
        unmapped_symbols: Vec::new(),
        unmapped_sources: Vec::new(),
        clone_fragments: fragments,
    }
}

/// Bytes divided across a symbol's source lines are a construction, so they
/// stay out of the bucket that says a byte count was observed.
#[test]
fn line_proportional_bytes_are_reported_apart_from_observed_bytes() {
    let rows = line_proportional_rows();

    let attributions = clone_group_attributions(&rows);

    assert_eq!(attributions.len(), 1);
    assert_eq!(attributions[0].attributed_noncanonical_members, 1);
    assert_eq!(attributions[0].duplicated_bytes, None);
    assert_eq!(attributions[0].estimated_duplicated_bytes, Some(9));

    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            7, &artifact, &rows,
        )));
    let json = serde_json::to_value(&report).unwrap();
    assert!(json["correlation"]["clone_group_attributions"][0]["duplicated_bytes"].is_null());
    assert_eq!(
        json["correlation"]["clone_group_attributions"][0]["estimated_duplicated_bytes"],
        9
    );
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains(
            "observed duplicated bytes: unavailable, line-proportional duplicated bytes: 9 (estimated)"
        ),
        "{text}"
    );
    assert!(
        text.contains("9 line-proportional estimated duplicate bytes"),
        "the estimate names the evidence its input came from: {text}"
    );

    let savings = clone_group_savings(&rows);
    assert_eq!(savings.len(), 1);
    assert_eq!(
        savings[0].duplicated_bytes_basis,
        AttributionBasis::LineProportional
    );
    let json = serde_json::to_value(&savings[0]).unwrap();
    assert_eq!(json["duplicated_bytes_basis"], "line_proportional");

    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    let mut csv_rows = csv.lines();
    let header = artifact_csv_fields(csv_rows.next().unwrap());
    let column = |name: &str| {
        header
            .iter()
            .position(|candidate| candidate == name)
            .unwrap()
    };
    let csv_rows: Vec<_> = csv_rows.map(artifact_csv_fields).collect();
    for record_type in ["clone-group-attribution", "clone-group-savings"] {
        let row = csv_rows
            .iter()
            .find(|row| row[0] == record_type)
            .expect("both clone-group records are written");
        assert_eq!(
            row[column("duplicated_bytes")],
            "",
            "{record_type} reported divided bytes as observed"
        );
        assert_eq!(row[column("estimated_duplicated_bytes")], "9");
        assert_eq!(
            row[column("attribution_basis")],
            "line_proportional_estimate"
        );
    }
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
        build_variant_fingerprint: [4; 16],
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
        build_variant_fingerprint: [5; 16],
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

/// A savings row reports the weakest mapping that paid into it, so a group
/// divided by source lines cannot read like one split exactly.
#[test]
fn savings_confidence_follows_the_weakest_contributing_mapping() {
    let rows = line_proportional_rows();

    let savings = clone_group_savings(&rows);

    assert_eq!(savings.len(), 1);
    assert_eq!(savings[0].duplicated_bytes, 9);
    assert_eq!(savings[0].mapping_confidence, EvidenceConfidence::Medium);
    assert_ne!(savings[0].mapping_confidence, EvidenceConfidence::High);
    let json = serde_json::to_value(&savings[0]).unwrap();
    let assumptions = json["assumptions"].as_array().unwrap();
    assert!(
        assumptions
            .iter()
            .any(|assumption| assumption["kind"] == "attribution_is_line_proportional"),
        "{json}"
    );
    let artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            7, &artifact, &rows,
        )));
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("mapping Medium"), "{text}");
    assert!(
        text.contains("divided across its symbol's source lines rather than observed"),
        "{text}"
    );
    let mut csv = Vec::new();
    render_csv(&report, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("attribution_is_line_proportional"), "{csv}");
}

/// An ambiguous mapping paid no bytes anyone can stand behind, so the group it
/// touched reports no savings row rather than a graded one.
#[test]
fn an_ambiguous_contributing_mapping_removes_the_savings_row() {
    let mut rows = line_proportional_rows();
    rows.mappings[0].evidence = MappingEvidence::new(
        vec![MappingEvidenceFact::Dwarf {
            source_path: "src/two.rs".to_owned(),
        }],
        2,
        false,
    );

    assert!(clone_group_savings(&rows).is_empty());
}

#[test]
fn refactoring_estimate_keeps_negative_overhead_outcomes_visible() {
    let mut model = refactor_savings_model();
    model.call_overhead_per_replaced_member_bytes = 12;
    assert_eq!(estimate_refactor_savings_bytes(9, 1, &model), -3);
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
            build_variant_fingerprint: [4; 16],
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/left.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([6; 16]),
            build_variant_fingerprint: [4; 16],
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
fn unreadable_debug_information_has_a_distinct_unmapped_reason() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"one"),
        name: None,
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
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.capabilities.debug_info_unreadable = true;
    artifact.symbols.push(symbol);

    let rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &[],
        &[],
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );

    assert_eq!(rows.unmapped_symbols.len(), 1);
    assert_eq!(
        rows.unmapped_symbols[0].reason,
        ArtifactAnalysisUnmappedReason::DebugInfoUnreadable
    );
}

#[test]
fn resolved_wasm_source_map_token_is_persisted_as_direct_mapping_evidence() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"wasm"),
        name: None,
        exported: false,
        section: Some(10),
        offset: 12,
        size: 3,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.symbols.push(symbol);
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/lib.rs".to_owned(),
        name: None,
        start_line: Some(5),
        end_line: Some(5),
    }];
    let mut rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );
    enrich_source_map_evidence(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[SourceMapLocation {
            generated_offset: 12,
            source_url: "src/lib.rs".to_owned(),
            source_line: Some(5),
        }],
        BuildVariantFingerprint::from_bytes([5; 16]),
        &mut rows,
    );

    assert!(rows.unmapped_symbols.is_empty());
    assert_eq!(rows.mappings.len(), 1);
    assert_eq!(
        rows.mappings[0].evidence.facts,
        vec![MappingEvidenceFact::SourceMap {
            source_url: "src/lib.rs".to_owned(),
        }]
    );
}

/// Build one symbol whose identity follows only from its content, so two
/// entries created from the same bytes share a fingerprint.
fn duplicated_symbol(offset: u64) -> codehelion_artifact::ArtifactSymbol {
    codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"duplicate"),
        name: Some("render".to_owned()),
        exported: false,
        section: Some(1),
        offset,
        size: 8,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
            evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
            source: "/work/src/render.cpp".to_owned(),
            line: Some(12),
            column: None,
        }],
    }
}

#[test]
fn content_identical_symbol_entries_keep_one_row_per_stored_mapping_identity() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"duplicate-symbols");
    artifact.symbols = vec![duplicated_symbol(0), duplicated_symbol(8)];
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: [4; 16],
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
        build_variant_fingerprint: [4; 16],
        file_path: "src/render.cpp".to_owned(),
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

    let stored_keys: Vec<_> = rows
        .mappings
        .iter()
        .map(|mapping| {
            (
                mapping.schema_version.clone(),
                mapping.artifact_symbol_fingerprint,
                source_kind_order(mapping.source_kind),
                mapping.source_fingerprint,
                mapping.source_instance_fingerprint,
                serde_json::to_string(&mapping.evidence).unwrap(),
            )
        })
        .collect();
    assert_eq!(
        stored_keys.iter().collect::<BTreeSet<_>>().len(),
        stored_keys.len(),
        "the stored uniqueness key must select at most one mapping"
    );
    assert_eq!(rows.mappings.len(), 2);
}

#[test]
fn duplicated_symbol_entries_survive_persistence() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"duplicate-symbols");
    artifact.symbols = vec![duplicated_symbol(0), duplicated_symbol(8)];
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/render.cpp".to_owned(),
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
    let symbols: Vec<_> = artifact
        .symbols
        .iter()
        .map(|symbol| ArtifactAnalysisSymbol {
            fingerprint: symbol.fingerprint.as_bytes(),
            name: symbol.name.clone(),
            exported: symbol.exported,
            section_index: symbol.section,
            offset: symbol.offset,
            size_bytes: symbol.size,
            size_inferred: symbol.size_inferred,
            code_fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "artifact-code",
                &symbol.code,
            )
            .as_bytes(),
            normalization_version: None,
            normalization_fingerprint: None,
        })
        .collect();
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(&directory.path().join("artifact.db")).unwrap();

    let analysis = store
        .record_artifact_analysis(&ArtifactAnalysisSnapshot {
            schema_version: &artifact.schema_version,
            path: "fixture.so",
            format: artifact.format.name(),
            content_fingerprint: artifact.fingerprint.as_bytes(),
            observed_bytes: artifact.observed_bytes,
            ir_json: &serde_json::to_string(&artifact).unwrap(),
            build_variant_manifest_path: None,
            build_variant_fingerprint: None,
            started_at: "2026-01-01T00:00:00Z",
            finished_at: "2026-01-01T00:00:01Z",
            symbols: &symbols,
            source_maps: &[],
            containment: None,
            mappings: &rows.mappings,
            unmapped_symbols: &rows.unmapped_symbols,
            unmapped_sources: &rows.unmapped_sources,
            correlation: None,
            clone_group_savings: &[],
        })
        .expect("content-identical symbols must not lose the whole analysis");

    assert!(analysis > 0);
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
            build_variant_fingerprint: [4; 16],
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/left.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(10),
            end_line: Some(20),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([3; 16]),
            build_variant_fingerprint: [4; 16],
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

#[test]
fn source_map_evidence_removes_a_unit_from_the_unmapped_source_side() {
    let symbol = codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"wasm"),
        name: None,
        exported: false,
        section: Some(10),
        offset: 12,
        size: 3,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    };
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.symbols.push(symbol);
    let units = [SourceUnitIdentity {
        fingerprint: UnitFingerprint::from_bytes([3; 16]),
        build_variant_fingerprint: [4; 16],
        unit_kind: "function".to_owned(),
        occurrence_ordinal: 1,
        file_path: "src/lib.rs".to_owned(),
        name: None,
        start_line: Some(5),
        end_line: Some(5),
    }];
    let mut rows = correlate_debug_locations(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[],
        &[],
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
    );
    assert_eq!(rows.unmapped_sources.len(), 1);

    enrich_source_map_evidence(
        &artifact,
        FilePath::new("/work"),
        &units,
        &[],
        &[SourceMapLocation {
            generated_offset: 12,
            source_url: "src/lib.rs".to_owned(),
            source_line: Some(5),
        }],
        BuildVariantFingerprint::from_bytes([5; 16]),
        &mut rows,
    );
    reconcile_unmapped_sources(&units, &[], &mut rows);

    let mapped: BTreeSet<_> = rows
        .mappings
        .iter()
        .map(|mapping| {
            (
                source_kind_order(mapping.source_kind),
                mapping.source_instance_fingerprint,
            )
        })
        .collect();
    let unmapped: BTreeSet<_> = rows
        .unmapped_sources
        .iter()
        .map(|source| {
            (
                source_kind_order(source.source_kind),
                source.source_instance_fingerprint,
            )
        })
        .collect();
    assert_eq!(mapped.len(), 1);
    assert!(
        mapped.is_disjoint(&unmapped),
        "a source identity belongs to exactly one side"
    );
    assert!(unmapped.is_empty());
    let correlation = ArtifactCorrelationReport::from_rows(7, &artifact, &rows);
    assert_eq!(correlation.source_entities, 1);
    assert_eq!(correlation.unmapped_sources, 0);
}

/// Record one completed scan run holding the given `(file path, name)` units,
/// and hand back the database it lives in together with its run id.
///
/// The correlation under test reads its source side from storage, so the run
/// has to exist as rows rather than as a value the caller assembled.
fn source_run_with_units(
    directory: &std::path::Path,
    units: &[(&str, Option<&str>)],
) -> (Store, i64) {
    let variant = codehelion_core::discovery::BuildVariant::fast(
        codehelion_core::discovery::LanguageSelection::default(),
        codehelion_core::discovery::Language::Rust,
    );
    let units = units
        .iter()
        .enumerate()
        .map(
            |(position, (file_path, name))| codehelion_store::snapshot::UnitRow {
                fingerprint: UnitFingerprint::from_bytes(
                    [3_u8.wrapping_add(u8::try_from(position).unwrap()); 16],
                ),
                language: codehelion_core::discovery::Language::Rust,
                kind: codehelion_core::frontend::UnitKind::Function,
                name: name.map(ToOwned::to_owned),
                file_path: (*file_path).to_owned(),
                start_line: 5,
                end_line: 5,
                token_count: 20,
            },
        )
        .collect();
    let mut store = Store::open(&directory.join("audit.db")).unwrap();
    let run = store
        .record_snapshot(&codehelion_store::snapshot::Snapshot {
            root_path: "/work",
            tool_version: "0.0.0",
            config_hash: "cfg-hash",
            config_source: "defaults",
            config_path: None,
            started_at: "2026-01-01T00:00:00Z",
            finished_at: "2026-01-01T00:00:01Z",
            variant: &variant,
            min_clone_tokens: 20,
            detector_versions: &[],
            suppressions: Vec::new(),
            units,
            groups: Vec::new(),
            sibling_groups: Vec::new(),
            near_misses: Vec::new(),
            files: Vec::new(),
            compiler_helpers: Vec::new(),
            compiler_units: Vec::new(),
            summary: codehelion_store::snapshot::SummaryRow::default(),
        })
        .unwrap();
    (store, run)
}

/// The build-condition evidence a source-run correlation is qualified by.
fn correlation_build_variant() -> BuildVariantEvidence {
    BuildVariantEvidence {
        manifest_path: "build-variant.json".to_owned(),
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
            "build-variant",
            b"one",
        ),
    }
}

/// Assert the split a completed correlation reports: every source identity is
/// on exactly one side, and the counted report agrees with it.
fn assert_one_side_per_source_identity(
    rows: &CorrelationRows,
    artifact: &ArtifactIr,
    source_run: i64,
    expected_mapped: usize,
) {
    let mapped: BTreeSet<_> = rows
        .mappings
        .iter()
        .map(|mapping| {
            (
                source_kind_order(mapping.source_kind),
                mapping.source_instance_fingerprint,
            )
        })
        .collect();
    let unmapped: BTreeSet<_> = rows
        .unmapped_sources
        .iter()
        .map(|source| {
            (
                source_kind_order(source.source_kind),
                source.source_instance_fingerprint,
            )
        })
        .collect();
    assert_eq!(mapped.len(), expected_mapped);
    assert!(
        mapped.is_disjoint(&unmapped),
        "a source identity belongs to exactly one side"
    );
    assert!(unmapped.is_empty());
    let correlation = ArtifactCorrelationReport::from_rows(source_run, artifact, rows);
    assert_eq!(correlation.source_entities, expected_mapped);
    assert_eq!(correlation.unmapped_sources, 0);
}

/// A correlation splits its source side once, when every pass that can still
/// establish a correspondence has run. Source-map tokens are the only artifact
/// evidence a build without native debug information offers, so a unit they
/// reach must leave the side that reports units no evidence reached.
#[test]
fn a_source_map_correspondence_settles_which_side_the_unit_is_reported_on() {
    let directory = tempfile::tempdir().unwrap();
    let (store, run) = source_run_with_units(directory.path(), &[("src/lib.rs", None)]);
    let mut artifact = ArtifactIr::empty(BinaryFormat::Wasm, b"fixture");
    artifact.symbols.push(codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"wasm"),
        name: None,
        exported: false,
        section: Some(10),
        offset: 12,
        size: 3,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    });

    let rows = correlate_source_run(
        &artifact,
        &[SourceMapLocation {
            generated_offset: 12,
            source_url: "src/lib.rs".to_owned(),
            source_line: Some(5),
        }],
        Some(run),
        Some(&correlation_build_variant()),
        &[],
        &store,
    )
    .expect("a recorded scan run correlates against the artifact");

    assert!(rows.mappings.iter().any(|mapping| {
        mapping.evidence.facts.iter().any(|fact| {
            matches!(fact, MappingEvidenceFact::SourceMap { source_url } if source_url == "src/lib.rs")
        })
    }));
    assert_one_side_per_source_identity(&rows, &artifact, run, 1);
}

/// Linker-map placement is the other evidence that arrives after the debug
/// locations were read. A symbol whose debug information names one file and
/// whose map entry places it in another object establishes a correspondence
/// for a second unit, and that unit must leave the no-evidence side too.
#[test]
fn a_linker_map_correspondence_settles_which_side_the_unit_is_reported_on() {
    let directory = tempfile::tempdir().unwrap();
    let (store, run) = source_run_with_units(
        directory.path(),
        &[
            ("src/inlined.rs", Some("render")),
            ("src/placed.rs", Some("render")),
        ],
    );
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", b"elf"),
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
            evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
            source: "/work/src/inlined.rs".to_owned(),
            line: Some(5),
            column: None,
        }],
    });

    let rows = correlate_source_run(
        &artifact,
        &[],
        Some(run),
        Some(&correlation_build_variant()),
        &[LinkerMapEntry {
            symbol: "render".to_owned(),
            object_path: "src/placed.rs.o".to_owned(),
        }],
        &store,
    )
    .expect("a recorded scan run correlates against the artifact");

    assert!(rows.mappings.iter().any(|mapping| {
        mapping.evidence.facts.iter().any(|fact| {
            matches!(fact, MappingEvidenceFact::LinkerMap { object_path } if object_path == "src/placed.rs.o")
        })
    }));
    assert_one_side_per_source_identity(&rows, &artifact, run, 2);
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
        build_variant_fingerprint: [4; 16],
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
        build_variant_fingerprint: [4; 16],
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
        build_variant_fingerprint: [4; 16],
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

/// Sizes of one correlation input, taken from an optimized real binary.
struct CorrelationScale {
    files: usize,
    symbols: usize,
    units: usize,
    fragments: usize,
    source_map_entries: usize,
    compiler_facts: usize,
}

/// The correlation input one `artifact analyze --source-run` receives.
struct CorrelationInput {
    artifact: ArtifactIr,
    units: Vec<SourceUnitIdentity>,
    fragments: Vec<SourceFragmentIdentity>,
    instantiations: Vec<SourceInstantiation>,
    resolved_symbols: Vec<SourceResolvedSymbol>,
    resolved_calls: Vec<SourceResolvedCall>,
    locations: Vec<SourceMapLocation>,
}

/// Build a correlation input of the requested size.
///
/// Sources are spread over many files and symbols land on many source lines, so
/// the answer to any one location question stays small. What grows here is the
/// number of questions and the number of recorded sources, which is the pairing
/// a per-symbol rescan turns into a product.
#[allow(
    clippy::too_many_lines,
    reason = "one fixture describes one whole input"
)]
fn correlation_input(scale: &CorrelationScale) -> CorrelationInput {
    let file_path = |index: usize| format!("src/module{}.rs", index % scale.files);
    let units: Vec<_> = (0..scale.units)
        .map(|position| {
            let ordinal = u32::try_from(position / scale.files).unwrap_or(u32::MAX);
            SourceUnitIdentity {
                fingerprint: UnitFingerprint::from_bytes(fingerprint_of("unit", position)),
                build_variant_fingerprint: [4; 16],
                unit_kind: "function".to_owned(),
                occurrence_ordinal: ordinal.saturating_add(1),
                file_path: file_path(position),
                name: Some(format!("unit{position}")),
                start_line: Some(ordinal.saturating_mul(20).saturating_add(1)),
                end_line: Some(ordinal.saturating_mul(20).saturating_add(16)),
            }
        })
        .collect();
    let fragments: Vec<_> = (0..scale.fragments)
        .map(|position| {
            let ordinal = u32::try_from(position / scale.files).unwrap_or(u32::MAX);
            SourceFragmentIdentity {
                fingerprint: FragmentFingerprint::from_bytes(fingerprint_of("fragment", position)),
                finding_id: FindingId::from_bytes(fingerprint_of("finding", position)),
                clone_group_fingerprint: CloneGroupFingerprint::from_bytes(fingerprint_of(
                    "group",
                    position / 2,
                )),
                is_canonical: position % 2 == 0,
                clone_confidence: 1.0,
                build_variant_fingerprint: [4; 16],
                file_path: file_path(position),
                start_line: Some(ordinal.saturating_mul(20).saturating_add(2)),
                end_line: Some(ordinal.saturating_mul(20).saturating_add(12)),
            }
        })
        .collect();
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"scale");
    artifact.symbols.extend((0..scale.symbols).map(|position| {
        // Every tenth symbol names a line no source unit covers, which is the
        // shape that falls through to the compiler-evidence passes.
        let unmapped = position % 10 == 0;
        let line = if unmapped {
            u32::MAX
        } else {
            u32::try_from(position / scale.files).unwrap_or(u32::MAX) % 20 * 20 + 4
        };
        let name = if position % 20 == 0 {
            format!("crate::render{position}::<String>")
        } else {
            format!("helper{position}")
        };
        codehelion_artifact::ArtifactSymbol {
            fingerprint: codehelion_artifact::ArtifactFingerprint::from_content(
                "symbol",
                &position.to_le_bytes(),
            ),
            name: Some(name),
            exported: false,
            section: Some(1),
            offset: u64::try_from(position)
                .unwrap_or(u64::MAX)
                .saturating_mul(16),
            size: 16,
            size_inferred: false,
            code: Vec::new(),
            normalized: None,
            body_fingerprint: None,
            inline_stack: vec![codehelion_artifact::ArtifactInlineFrame {
                evidence_kind: codehelion_artifact::ArtifactSourceLocationEvidenceKind::Dwarf,
                source: format!("/work/{}", file_path(position)),
                line: Some(line),
                column: None,
            }],
        }
    }));
    let instantiations = (0..scale.compiler_facts)
        .map(|position| SourceInstantiation {
            definition: format!("crate::render{position}"),
            artifact_match_key: None,
            instantiation_key: format!("crate::render{position}::<String>"),
            file_path: format!("/work/{}", file_path(position)),
            line: 4,
            definition_end_line: Some(16),
            translation_unit: format!("src/module{position}.rs"),
        })
        .collect();
    let resolved_symbols = (0..scale.compiler_facts)
        .map(|position| SourceResolvedSymbol {
            name: format!("helper{position}"),
            file_path: format!("/work/{}", file_path(position)),
            line: 4,
            macro_definition: None,
        })
        .collect();
    let resolved_calls = (0..scale.compiler_facts)
        .map(|position| SourceResolvedCall {
            target_name: format!("helper{position}"),
            file_path: format!("/work/{}", file_path(position)),
            line: 4,
        })
        .collect();
    let generated_span = u64::try_from(scale.symbols)
        .unwrap_or(u64::MAX)
        .saturating_mul(16);
    let locations = (0..scale.source_map_entries)
        .map(|position| SourceMapLocation {
            generated_offset: u64::try_from(position)
                .unwrap_or(u64::MAX)
                .saturating_mul(4)
                % generated_span.max(1),
            source_url: format!("/work/{}", file_path(position)),
            source_line: Some(4),
        })
        .collect();
    CorrelationInput {
        artifact,
        units,
        fragments,
        instantiations,
        resolved_symbols,
        resolved_calls,
        locations,
    }
}

/// A distinct stable identity for one fixture record.
fn fingerprint_of(domain: &str, position: usize) -> [u8; 16] {
    codehelion_artifact::ArtifactFingerprint::from_content(domain, &position.to_le_bytes())
        .as_bytes()
}

/// One source-run correlation at the scale of an optimized real binary.
///
/// Parsing, correlation, persistence, and rendering share one deadline, so the
/// work correlation does decides whether the command finishes at all. Every
/// pass here visits each artifact symbol; rescanning a whole input list inside
/// those visits makes the work the product of two input sizes rather than
/// their sum, and at these sizes that product is the difference between
/// seconds and a timeout no flag can raise usefully.
#[test]
fn source_run_correlation_stays_within_the_analysis_deadline() {
    let input = correlation_input(&CorrelationScale {
        files: 2_000,
        symbols: 50_000,
        units: 20_000,
        fragments: 4_000,
        source_map_entries: 200_000,
        compiler_facts: 5_000,
    });

    let started = std::time::Instant::now();
    let mut rows = correlate_debug_locations(
        &input.artifact,
        FilePath::new("/work"),
        &input.units,
        &input.fragments,
        &input.instantiations,
        &input.resolved_symbols,
        &input.resolved_calls,
        BuildVariantFingerprint::from_bytes([5; 16]),
    );
    enrich_source_map_evidence(
        &input.artifact,
        FilePath::new("/work"),
        &input.units,
        &input.fragments,
        &input.locations,
        BuildVariantFingerprint::from_bytes([5; 16]),
        &mut rows,
    );
    enrich_linker_map_evidence(
        &input.artifact,
        &input.units,
        &[],
        BuildVariantFingerprint::from_bytes([5; 16]),
        &mut rows,
    );
    reconcile_unmapped_sources(&input.units, &input.fragments, &mut rows);
    let elapsed = started.elapsed();

    assert!(
        !rows.mappings.is_empty(),
        "the measured correlation established no mapping at all"
    );
    assert!(
        elapsed < Duration::from_secs(DEFAULT_ARTIFACT_TIMEOUT_SECONDS),
        "correlating {} symbols against {} units and {} source-map entries took {elapsed:?}",
        input.artifact.symbols.len(),
        input.units.len(),
        input.locations.len(),
    );
}
