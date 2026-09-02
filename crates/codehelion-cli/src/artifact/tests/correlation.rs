use super::*;

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
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
            unit_kind: "function".to_owned(),
            occurrence_ordinal: 1,
            file_path: "src/render.cpp".to_owned(),
            name: Some("render".to_owned()),
            start_line: Some(1),
            end_line: Some(10),
        },
        SourceUnitIdentity {
            fingerprint: UnitFingerprint::from_bytes([6; 16]),
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
            source_build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
            build_variant_fingerprint: BuildVariantFingerprint::from_bytes([5; 16]),
        }],
        unmapped_symbols: Vec::new(),
        unmapped_sources: Vec::new(),
        clone_fragments: fragments,
    }
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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

/// A symbol of `size` bytes, identified the way a parse identifies one.
fn sized_symbol(
    content: &[u8],
    name: Option<&str>,
    size: u64,
) -> codehelion_artifact::ArtifactSymbol {
    codehelion_artifact::ArtifactSymbol {
        fingerprint: codehelion_artifact::ArtifactFingerprint::from_content("symbol", content),
        name: name.map(ToOwned::to_owned),
        exported: false,
        section: Some(1),
        offset: 0,
        size,
        size_inferred: false,
        code: Vec::new(),
        normalized: None,
        body_fingerprint: None,
        inline_stack: Vec::new(),
    }
}

/// A symbol with no usable name could not have been matched by name, and no
/// debug information anyone supplies would give it one.
///
/// Stripping a WebAssembly name section leaves exactly this symbol. Reporting it
/// as missing debug information sends its owner after the wrong artifact.
#[test]
fn a_symbol_without_a_usable_name_is_not_reported_as_missing_debug_information() {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    artifact.symbols.push(sized_symbol(b"nameless", None, 5));
    artifact
        .symbols
        .push(sized_symbol(b"named", Some("unmatched"), 7));

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

    let reasons: Vec<_> = rows
        .unmapped_symbols
        .iter()
        .map(|unmapped| unmapped.reason)
        .collect();
    assert!(
        reasons.contains(&ArtifactAnalysisUnmappedReason::DemangleFailed),
        "{reasons:?}"
    );
    assert!(
        reasons.contains(&ArtifactAnalysisUnmappedReason::DebugInfoMissing),
        "{reasons:?}"
    );
}

mod attribution;
mod matching;
mod origin;
mod ratio;
mod savings;
mod scale;
