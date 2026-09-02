//! Generic and template origins: instantiation keys, metrics, and arguments.

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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
