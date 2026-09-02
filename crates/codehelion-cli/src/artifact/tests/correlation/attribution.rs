//! Clone-group attribution and multiply emitted source units.

use super::*;

#[test]
fn group_attribution_reports_exact_noncanonical_byte_splits() {
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
    let rows = CorrelationRows {
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
                    MappingEvidenceFact::WholeSymbolAttribution,
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
    };

    assert_eq!(
        clone_group_attributions(&ArtifactIr::empty(BinaryFormat::Elf, b"fixture"), &rows)
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

/// Bytes divided across a symbol's source lines are a construction, so they
/// stay out of the bucket that says a byte count was observed.
#[test]
fn line_proportional_bytes_are_reported_apart_from_observed_bytes() {
    let rows = line_proportional_rows();

    let attributions =
        clone_group_attributions(&ArtifactIr::empty(BinaryFormat::Elf, b"fixture"), &rows);

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

/// One name-established mapping from a source unit to an artifact symbol.
fn named_unit_mapping(
    symbol: &codehelion_artifact::ArtifactSymbol,
    candidate_count: u32,
) -> ArtifactAnalysisMapping {
    ArtifactAnalysisMapping {
        schema_version: SOURCE_ARTIFACT_MAPPING_SCHEMA_VERSION.to_owned(),
        artifact_symbol_fingerprint: symbol.fingerprint.as_bytes(),
        source_kind: ArtifactAnalysisSourceKind::Unit,
        source_fingerprint: [2; 16],
        source_instance_fingerprint: [11; 16],
        source_build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
        evidence: MappingEvidence::new(
            vec![MappingEvidenceFact::SymbolName {
                source_symbol: "firstEntryFrom".to_owned(),
                artifact_symbol: "firstEntryFrom".to_owned(),
            }],
            candidate_count,
            false,
        ),
        attributed_bytes: None,
        build_variant_fingerprint: BuildVariantFingerprint::from_bytes([5; 16]),
    }
}

/// An artifact holding `symbols`, and the rows that map them to one unit.
fn one_unit_emitted_as(sizes: &[u64], candidate_count: u32) -> (ArtifactIr, CorrelationRows) {
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let mut mappings = Vec::new();
    for (ordinal, size) in sizes.iter().enumerate() {
        let symbol = sized_symbol(
            format!("body-{ordinal}").as_bytes(),
            Some("firstEntryFrom"),
            *size,
        );
        mappings.push(named_unit_mapping(&symbol, candidate_count));
        artifact.symbols.push(symbol);
    }
    (
        artifact,
        CorrelationRows {
            mappings,
            unmapped_symbols: Vec::new(),
            unmapped_sources: Vec::new(),
            clone_fragments: Vec::new(),
        },
    )
}

/// A source copy and an emitted body are separate populations, and the second
/// is the one a size reader is spending bytes on.
///
/// One generic written once becomes one body per instantiation. Nothing in the
/// duplicate counts can express that, because there is only ever one copy of the
/// source to count, so the fan-out of the correspondence is reported directly.
#[test]
fn a_source_unit_the_artifact_emitted_several_times_is_reported_with_their_observed_bytes() {
    let (artifact, rows) = one_unit_emitted_as(&[10, 20, 30], 1);

    let units = multiply_emitted_units(&artifact, &rows);

    assert_eq!(units.len(), 1);
    assert_eq!(units[0].emitted_bodies, 3);
    assert_eq!(units[0].observed_symbol_bytes, 60);
    assert_eq!(units[0].name.as_deref(), Some("firstEntryFrom"));
    assert_eq!(units[0].source_fingerprint, fingerprint_hex([2; 16]));
    assert_eq!(units[0].mapping_confidence, EvidenceConfidence::Low);
}

/// A unit emitted once says nothing that reading the source did not, and there
/// are as many of those as there are functions.
#[test]
fn a_source_unit_emitted_once_is_not_reported_as_multiply_emitted() {
    let (artifact, rows) = one_unit_emitted_as(&[10], 1);

    assert!(multiply_emitted_units(&artifact, &rows).is_empty());
}

/// An ambiguous mapping named several source units and chose none, so counting
/// it would raise the emitted-body count of every one of them at once.
#[test]
fn an_ambiguous_mapping_does_not_raise_a_units_emitted_body_count() {
    let (artifact, rows) = one_unit_emitted_as(&[10, 20, 30], 2);

    assert!(multiply_emitted_units(&artifact, &rows).is_empty());
}

/// A format carrying symbol names but no line frames still settles which symbol
/// holds a clone group's members.
///
/// This is the shape a shipped WebAssembly binary takes: the name section
/// survives, DWARF does not, and reporting the group as reached by no artifact
/// evidence throws away a correspondence that was established.
#[test]
fn a_group_matched_only_by_name_reports_the_symbols_that_hold_its_members() {
    let symbol = sized_symbol(b"holder", Some("firstEntryFrom"), 48);
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let mut rows = line_proportional_rows();
    // The name settled the symbol; without line frames nothing divided its
    // bytes, which is exactly what leaves `attributed_bytes` absent.
    rows.mappings[0].artifact_symbol_fingerprint = symbol.fingerprint.as_bytes();
    rows.mappings[0].attributed_bytes = None;
    rows.mappings[0].evidence = MappingEvidence::new(
        vec![MappingEvidenceFact::SymbolName {
            source_symbol: "firstEntryFrom".to_owned(),
            artifact_symbol: "firstEntryFrom".to_owned(),
        }],
        1,
        false,
    );
    artifact.symbols.push(symbol);

    let attributions = clone_group_attributions(&artifact, &rows);

    assert_eq!(attributions.len(), 1);
    assert_eq!(attributions[0].duplicated_bytes, None);
    assert_eq!(attributions[0].estimated_duplicated_bytes, None);
    assert_eq!(attributions[0].containing_symbols, 1);
    assert_eq!(attributions[0].containing_symbol_bytes, Some(48));
}

/// The containing symbol holds the member and is not the member, so its size
/// bounds what the group occupies instead of measuring it.
#[test]
fn a_containing_symbol_size_is_reported_apart_from_every_duplicated_byte_total() {
    let symbol = sized_symbol(b"holder", Some("firstEntryFrom"), 48);
    let mut artifact = ArtifactIr::empty(BinaryFormat::Elf, b"fixture");
    let mut rows = line_proportional_rows();
    rows.mappings[0].artifact_symbol_fingerprint = symbol.fingerprint.as_bytes();
    artifact.symbols.push(symbol);

    let report = ArtifactReport::from_ir(FilePath::new("fixture.so"), &artifact, None, None)
        .with_correlation(Some(ArtifactCorrelationReport::from_rows(
            7, &artifact, &rows,
        )));

    let json = serde_json::to_value(&report).unwrap();
    let attribution = &json["correlation"]["clone_group_attributions"][0];
    // The line-proportional total stays the estimate it was, and the size of
    // the symbol holding the member never stands in for it.
    assert_eq!(attribution["estimated_duplicated_bytes"], 9);
    assert!(attribution["duplicated_bytes"].is_null());
    assert_eq!(attribution["containing_symbol_bytes"], 48);
    let mut text = Vec::new();
    render_text(&report, false, &mut text).unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(
        text.contains("in 1 symbol(s) totalling 48 observed bytes"),
        "{text}"
    );
    assert!(
        text.contains("bounds what the group occupies rather than measuring it"),
        "{text}"
    );
}
