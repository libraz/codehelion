//! One source-run correlation at the scale of an optimized real binary.

use super::*;
use crate::cli::DEFAULT_ARTIFACT_TIMEOUT_SECONDS;
use codehelion_store::query::SourceResolvedSymbol;

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
                build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
                build_variant_fingerprint: BuildVariantFingerprint::from_bytes([4; 16]),
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
