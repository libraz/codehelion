use super::regions::Dropped;
use super::reporting::{group_detail, group_fingerprint};
use super::{
    Boilerplate, CloneClass, Confirmed, CrossVariantUnit, RegionOccurrence, RegionSide,
    ResolvedTypes, StructuralConfig, StructuralRegion, Unit, compare_build_variants, covers_run,
    dominant_boilerplate, drop_subsumed, features, flatten_units, fold_by_content,
    is_allocation_api, merge_adjacent, set_jaccard, unit_evidence, unrepresented_pairs, view,
};
use crate::candidate::StatementRun;
use crate::conditional::ArmPath;
use crate::discovery::{BuildVariant, Language, LanguageSelection};
use crate::engine::{LiteralNorm, normalize::Resolution};
use crate::frontend::{SourceSpan, Token, TokenKind, UnitKind};
use crate::grouping;
use crate::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, SyntaxIrFile};
use crate::stable_id::{CloneGroupFingerprint, FragmentFingerprint, UnitFingerprint};
use crate::types::TypeTag;
use crate::verify::{Confidence, SimilarityBreakdown};
use std::collections::BTreeSet;

fn occurrence(file: usize, start: usize, end: usize) -> RegionOccurrence {
    RegionOccurrence {
        file,
        unit: 0,
        range: ByteRange { start, end },
        start_line: 1,
        end_line: 2,
        token_start: start,
        token_end: end,
        content: FragmentFingerprint::from_bytes(
            [u8::try_from(start % 251).expect("bounded occurrence offset"); 16],
        ),
    }
}

#[test]
fn identifier_jaccard_compares_raw_identifier_sets() {
    let first = BTreeSet::from(["candidate", "token", "value"]);
    let second = BTreeSet::from(["candidate", "other", "value"]);
    let empty = BTreeSet::new();

    assert!((set_jaccard(&first, &first) - 1.0).abs() < f64::EPSILON);
    assert!((set_jaccard(&first, &second) - 0.5).abs() < f64::EPSILON);
    assert!((set_jaccard(&empty, &empty) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn allocation_evidence_accepts_explicit_apis_without_guessing_wrappers() {
    assert!(is_allocation_api(&"with_capacity".into()));
    assert!(is_allocation_api(&"malloc".into()));
    assert!(!is_allocation_api(&"build_buffer".into()));
}

fn region(
    id: u8,
    clone_type: CloneClass,
    statements: u32,
    spans: &[(usize, usize, usize)],
) -> StructuralRegion {
    StructuralRegion {
        fingerprint: CloneGroupFingerprint::from_bytes([id; 16]),
        clone_type,
        statements,
        occurrences: spans
            .iter()
            .map(|&(file, start, end)| occurrence(file, start, end))
            .collect(),
    }
}

fn ids(regions: &[StructuralRegion]) -> Vec<u8> {
    regions
        .iter()
        .map(|region| region.fingerprint.as_bytes()[0])
        .collect()
}

fn unit_at(file: usize, start: usize, end: usize) -> Unit {
    Unit {
        file,
        local: 0,
        kind: UnitKind::Function,
        statements: Vec::new(),
        fingerprint: UnitFingerprint::from_bytes([0; 16]),
        content: FragmentFingerprint::from_bytes([0; 16]),
        normalized_content: FragmentFingerprint::from_bytes([0; 16]),
        range: ByteRange { start, end },
        lines: (1, 2),
        tokens: (0, 0),
        name: None,
        boilerplate: None,
        test_code: false,
        test_code_evidence: None,
        arms: ArmPath::default(),
    }
}

#[test]
fn structural_non_exact_group_ids_survive_consistent_renames() {
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Cpp,
    );
    let group = grouping::StructuralGroup {
        clone_type: CloneClass::Type2,
        confidence: Confidence::High,
        canonical: 0,
        medoid_similarities: vec![1.0, 0.9],
        min_pairwise: 0.9,
        members: vec![0, 1],
    };
    let corpus = |raw_a, raw_b| {
        vec![
            Unit {
                content: FragmentFingerprint::from_bytes([raw_a; 16]),
                normalized_content: FragmentFingerprint::from_bytes([7; 16]),
                ..unit_at(0, 0, 10)
            },
            Unit {
                content: FragmentFingerprint::from_bytes([raw_b; 16]),
                normalized_content: FragmentFingerprint::from_bytes([8; 16]),
                ..unit_at(1, 0, 10)
            },
        ]
    };
    let before = corpus(1, 2);
    let after = corpus(3, 4);

    assert_eq!(
        group_fingerprint(&group, &before, &variant),
        group_fingerprint(&group, &after, &variant),
    );

    let exact_group = grouping::StructuralGroup {
        clone_type: CloneClass::Type1,
        ..group
    };
    assert_ne!(
        group_fingerprint(&exact_group, &before, &variant),
        group_fingerprint(&exact_group, &after, &variant),
    );
}

fn grouped(members: Vec<usize>) -> grouping::StructuralGroup {
    grouping::StructuralGroup {
        clone_type: CloneClass::Type2,
        confidence: Confidence::High,
        canonical: 0,
        medoid_similarities: vec![1.0; members.len()],
        min_pairwise: 0.9,
        members,
    }
}

fn cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let tokens = words
        .iter()
        .enumerate()
        .map(|(index, word)| Token {
            kind: TokenKind::Identifier,
            text: (*word).into(),
            span: SourceSpan {
                start_byte: index * 8,
                end_byte: index * 8 + word.len(),
                start_line: 1,
                start_column: 1,
            },
        })
        .collect();
    let token_end = words.len();
    SyntaxIrFile {
        language: Language::Rust,
        frontend_version: "test",
        ir_schema_version: IR_SCHEMA_VERSION,
        tokens,
        roots: vec![IrNode {
            shape: Shape::Function,
            name: None,
            token_start: 0,
            token_end,
            range: ByteRange {
                start: 0,
                end: token_end * 8,
            },
            children: vec![IrNode {
                shape: Shape::Block,
                name: None,
                token_start: 0,
                token_end,
                range: ByteRange {
                    start: 0,
                    end: token_end * 8,
                },
                children: vec![IrNode {
                    shape: Shape::ExprStmt,
                    name: None,
                    token_start: 0,
                    token_end,
                    range: ByteRange {
                        start: 0,
                        end: token_end * 8,
                    },
                    children: Vec::new(),
                }],
            }],
        }],
        diagnostics: Vec::new(),
        error_ranges: Vec::new(),
        depth_truncated: false,
        test_module: false,
    }
}

#[test]
fn group_cohesion_evidence_uses_the_weakest_noncanonical_pair() {
    let files = vec![
        cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
        cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "x"]),
        cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "y", "j"]),
    ];
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
    );
    let config = StructuralConfig::default();
    let feature_files: Vec<_> = files.iter().map(features::extract).collect();
    let (units, _) = flatten_units(&files, &variant, config.literals, &ResolvedTypes::default());
    let evidence = unit_evidence(&units, &ResolvedTypes::default());
    let canonical_to_first = crate::verify::verify(
        &view(0, &units, &files, &feature_files, &evidence),
        &view(1, &units, &files, &feature_files, &evidence),
        &config.verify,
    )
    .breakdown;
    let canonical_to_second = crate::verify::verify(
        &view(0, &units, &files, &feature_files, &evidence),
        &view(2, &units, &files, &feature_files, &evidence),
        &config.verify,
    )
    .breakdown;
    let weakest_pair = crate::verify::verify(
        &view(1, &units, &files, &feature_files, &evidence),
        &view(2, &units, &files, &feature_files, &evidence),
        &config.verify,
    )
    .breakdown;
    assert!(weakest_pair.composite < canonical_to_first.composite);
    assert!(weakest_pair.composite < canonical_to_second.composite);

    let group = grouping::StructuralGroup {
        clone_type: CloneClass::Type3,
        confidence: Confidence::High,
        canonical: 0,
        medoid_similarities: vec![
            1.0,
            canonical_to_first.composite,
            canonical_to_second.composite,
        ],
        min_pairwise: weakest_pair.composite,
        members: vec![0, 1, 2],
    };
    let detail = group_detail(
        &group,
        &units,
        &files,
        &feature_files,
        &evidence,
        &variant,
        &config,
    );

    assert_eq!(detail.cohesion_breakdown, weakest_pair);
    assert!((detail.cohesion_breakdown.composite - group.min_pairwise).abs() < f64::EPSILON);
}

#[test]
fn compiler_name_resolution_changes_semantic_unit_normalization() {
    let files = vec![cohesion_file(&["external_name"])];
    let variant = BuildVariant::semantic(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
        Vec::new(),
    );
    let (lexical, _) = flatten_units(
        &files,
        &variant,
        LiteralNorm::Full,
        &ResolvedTypes::default(),
    );
    let mut names = Resolution::new();
    names.insert(0, true);
    let resolved = ResolvedTypes::per_file_with_semantic_normalization(
        vec![Vec::new()],
        vec![Vec::new()],
        vec![names],
    );
    let (compiler_aware, _) = flatten_units(&files, &variant, LiteralNorm::Full, &resolved);

    assert_ne!(
        lexical[0].normalized_content,
        compiler_aware[0].normalized_content
    );
    assert_eq!(lexical[0].content, compiler_aware[0].content);
}

#[test]
fn a_dominant_boilerplate_shape_survives_a_small_number_of_exceptions() {
    let mut units = (0..5).map(|index| unit_at(index, 0, 0)).collect::<Vec<_>>();
    for unit in &mut units[..4] {
        unit.boilerplate = Some(Boilerplate::TrivialBody);
    }
    assert_eq!(
        dominant_boilerplate(&grouped(vec![0, 1, 2, 3, 4]), &units),
        Some(Boilerplate::TrivialBody)
    );
}

#[test]
fn a_non_dominant_shape_does_not_label_a_group() {
    let mut units = (0..5).map(|index| unit_at(index, 0, 0)).collect::<Vec<_>>();
    for unit in &mut units[..3] {
        unit.boilerplate = Some(Boilerplate::TrivialBody);
    }
    assert_eq!(
        dominant_boilerplate(&grouped(vec![0, 1, 2, 3, 4]), &units),
        None
    );
}

#[test]
fn an_unrepresented_pair_keeps_the_same_shape_classifications_as_a_group() {
    let names = ["u8", "u32", "u64"];
    let files: Vec<SyntaxIrFile> = names
        .iter()
        .map(|name| SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: vec![Token {
                kind: TokenKind::Identifier,
                text: (*name).into(),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: name.len(),
                    start_line: 1,
                    start_column: 1,
                },
            }],
            roots: Vec::new(),
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            depth_truncated: false,
            test_module: false,
        })
        .collect();
    let units: Vec<Unit> = (0..names.len())
        .map(|index| Unit {
            file: index,
            tokens: (0, 1),
            fingerprint: UnitFingerprint::from_bytes(
                [u8::try_from(index + 1).expect("small test index"); 16],
            ),
            content: FragmentFingerprint::from_bytes(
                [u8::try_from(index + 1).expect("small test index"); 16],
            ),
            boilerplate: Some(Boilerplate::MacroRepetition),
            ..unit_at(index, 0, names[index].len())
        })
        .collect();
    let grouping_units: Vec<grouping::GroupingUnit> = units
        .iter()
        .map(|unit| grouping::GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect();
    let edges = [
        grouping::SimilarityEdge {
            a: 0,
            b: 1,
            similarity: 0.9,
            breakdown: None,
            class: CloneClass::Type2,
            confidence: Confidence::High,
        },
        grouping::SimilarityEdge {
            a: 1,
            b: 2,
            similarity: 0.9,
            breakdown: None,
            class: CloneClass::Type2,
            confidence: Confidence::High,
        },
    ];
    let groups = grouping::group(
        &grouping_units,
        &edges,
        &grouping::GroupingConfig::default(),
    );
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Cpp,
    );
    let (pairs, _, _) = unrepresented_pairs(&edges, &groups, &units, &files, &variant);
    let pair = pairs
        .first()
        .expect("one verified edge remains outside a cohesive group");
    assert_eq!(pair.boilerplate, Some(Boilerplate::MacroRepetition));
    assert!(pair.width_family);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the folded-pair fixture keeps both crossings and their evidence together"
)]
fn an_unrepresented_pair_keeps_its_weakest_crossing_as_confidence() {
    // The two contents each occur twice. Structural evidence can differ
    // by occurrence (for example because compiler evidence is partial),
    // but the one split-pair finding speaks for every occurrence of both
    // contents and must therefore be conservative.
    let files: Vec<SyntaxIrFile> = (0..4)
        .map(|_| SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: vec![Token {
                kind: TokenKind::Identifier,
                text: "unit".into(),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: 1,
                    start_line: 1,
                    start_column: 1,
                },
            }],
            roots: Vec::new(),
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            depth_truncated: false,
            test_module: false,
        })
        .collect();
    let units: Vec<Unit> = (0..4)
        .map(|index| {
            let content = if index < 2 { 1 } else { 2 };
            Unit {
                file: index,
                tokens: (0, 1),
                fingerprint: UnitFingerprint::from_bytes([content; 16]),
                content: FragmentFingerprint::from_bytes([content; 16]),
                ..unit_at(index, 0, 1)
            }
        })
        .collect();
    let grouping_units: Vec<grouping::GroupingUnit> = units
        .iter()
        .map(|unit| grouping::GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect();
    let edges = [
        grouping::SimilarityEdge {
            a: 0,
            b: 2,
            similarity: 0.95,
            breakdown: Some(SimilarityBreakdown {
                lexical: 0.95,
                structural: 0.95,
                control_flow: Some(0.95),
                type_similarity: None,
                api: Some(0.95),
                composite: 0.95,
            }),
            class: CloneClass::Type3,
            confidence: Confidence::High,
        },
        grouping::SimilarityEdge {
            a: 1,
            b: 3,
            similarity: 0.75,
            breakdown: Some(SimilarityBreakdown {
                lexical: 0.70,
                structural: 0.80,
                control_flow: Some(0.75),
                type_similarity: None,
                api: Some(0.74),
                composite: 0.75,
            }),
            class: CloneClass::Type3,
            confidence: Confidence::Low,
        },
    ];
    let grouping = grouping::group(
        &grouping_units,
        &edges,
        &grouping::GroupingConfig {
            medoid_min_similarity: 0.98,
            min_pairwise_similarity: 0.98,
            ..grouping::GroupingConfig::default()
        },
    );
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Cpp,
    );

    let (pairs, _, _) = unrepresented_pairs(&edges, &grouping, &units, &files, &variant);

    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].members.len(), 4);
    assert!((pairs[0].similarity - 0.75).abs() < f64::EPSILON);
    assert_eq!(pairs[0].confidence, Confidence::Low);
    assert_eq!(
        pairs[0].breakdown,
        Some(SimilarityBreakdown {
            lexical: 0.70,
            structural: 0.80,
            control_flow: Some(0.75),
            type_similarity: None,
            api: Some(0.74),
            composite: 0.75,
        })
    );
}

/// Two units that differ only in their identifiers are one content to a
/// Type-3 relation, because that relation is judged on normalized content and
/// the group id is composed from it. Carrying a crossing against each of them
/// separately states one relation twice — and, since both statements compose
/// the same id, they used to arrive as two findings that could not both be
/// recorded.
#[test]
fn crossings_that_differ_only_where_normalization_erases_it_are_one_finding() {
    let files: Vec<SyntaxIrFile> = (0..3)
        .map(|_| SyntaxIrFile {
            language: Language::Rust,
            frontend_version: "test",
            ir_schema_version: IR_SCHEMA_VERSION,
            tokens: vec![Token {
                kind: TokenKind::Identifier,
                text: "unit".into(),
                span: SourceSpan {
                    start_byte: 0,
                    end_byte: 1,
                    start_line: 1,
                    start_column: 1,
                },
            }],
            roots: Vec::new(),
            diagnostics: Vec::new(),
            error_ranges: Vec::new(),
            depth_truncated: false,
            test_module: false,
        })
        .collect();
    // Units 0 and 1 are renamings of each other: distinct raw content, one
    // normalized content. Unit 2 is the other side of the relation.
    let units: Vec<Unit> = (0..3u8)
        .map(|index| {
            let position = usize::from(index);
            let normalized = if position < 2 { 10 } else { 20 };
            Unit {
                file: position,
                tokens: (0, 1),
                fingerprint: UnitFingerprint::from_bytes([index + 1; 16]),
                content: FragmentFingerprint::from_bytes([index + 1; 16]),
                normalized_content: FragmentFingerprint::from_bytes([normalized; 16]),
                ..unit_at(position, 0, 1)
            }
        })
        .collect();
    let grouping_units: Vec<grouping::GroupingUnit> = units
        .iter()
        .map(|unit| grouping::GroupingUnit {
            key: *unit.fingerprint.as_bytes(),
        })
        .collect();
    let crossing = |a: usize, b: usize| grouping::SimilarityEdge {
        a,
        b,
        similarity: 0.90,
        breakdown: Some(SimilarityBreakdown {
            lexical: 0.90,
            structural: 0.90,
            control_flow: Some(0.90),
            type_similarity: None,
            api: Some(0.90),
            composite: 0.90,
        }),
        class: CloneClass::Type3,
        confidence: Confidence::High,
    };
    let edges = [crossing(0, 2), crossing(1, 2)];
    let grouping = grouping::group(
        &grouping_units,
        &edges,
        &grouping::GroupingConfig {
            medoid_min_similarity: 0.98,
            min_pairwise_similarity: 0.98,
            ..grouping::GroupingConfig::default()
        },
    );
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Cpp,
    );

    let (pairs, _, _) = unrepresented_pairs(&edges, &grouping, &units, &files, &variant);

    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].members, vec![0, 1, 2]);
    // The anchor follows raw content, so it does not depend on which crossing
    // the walk reached first.
    assert_eq!(pairs[0].canonical, 0);
}

fn at(start: usize, end: usize, tag: TypeTag) -> (ByteRange, TypeTag) {
    (ByteRange { start, end }, tag)
}

/// A compiler answers about bytes; which unit those bytes are in is this
/// crate's reading of the tree, and the two are matched here.
#[test]
fn a_type_resolved_inside_a_unit_is_evidence_about_that_unit() {
    let resolved = ResolvedTypes::per_file(vec![vec![
        at(30, 33, TypeTag::Integer),
        at(10, 16, TypeTag::Text),
        at(90, 93, TypeTag::Integer),
    ]]);
    let evidence = resolved
        .within(&unit_at(0, 0, 40))
        .expect("two types were resolved inside it");
    assert_eq!(evidence.len(), 2);
    // The one at 90 belongs to whatever holds byte 90, not to this unit.
    let other = resolved
        .within(&unit_at(0, 80, 100))
        .expect("one type was resolved inside it");
    assert_eq!(other.len(), 1);
}

/// A unit nobody resolved anything in is compared as one nobody measured,
/// not as one measured to hold no types: the second would let a pair no
/// compiler spoke about claim the dimension's full weight.
#[test]
fn a_unit_no_compiler_spoke_about_has_no_evidence_rather_than_empty_evidence() {
    let resolved = ResolvedTypes::per_file(vec![vec![at(10, 16, TypeTag::Text)]]);
    assert!(resolved.within(&unit_at(0, 40, 80)).is_none());
    // A file nobody asked about at all.
    assert!(resolved.within(&unit_at(1, 0, 40)).is_none());
    assert!(
        ResolvedTypes::default()
            .within(&unit_at(0, 0, 40))
            .is_none()
    );
}

/// A range that starts in one unit and ends outside it describes neither,
/// so it is counted for neither.
#[test]
fn a_type_reaching_past_a_unit_is_not_counted_inside_it() {
    let resolved = ResolvedTypes::per_file(vec![vec![at(30, 60, TypeTag::Sequence)]]);
    assert!(resolved.within(&unit_at(0, 0, 40)).is_none());
}

#[test]
fn a_resolved_api_inside_a_unit_is_evidence_about_that_unit() {
    let resolved = ResolvedTypes::per_file_with_apis(
        vec![Vec::new()],
        vec![vec![
            (ByteRange { start: 30, end: 33 }, "static:kept".into()),
            (ByteRange { start: 90, end: 93 }, "static:other".into()),
        ]],
    );
    assert!(resolved.apis_within(&unit_at(0, 0, 40)).is_some());
    assert!(resolved.apis_within(&unit_at(0, 40, 80)).is_none());
}

#[test]
fn a_run_every_occurrence_of_which_sits_inside_a_longer_one_goes() {
    // The window lengths overlap, so one stretch confirms at several
    // lengths. The longest reports the same code in the same places.
    let mut regions = vec![
        region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
        region(2, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
    ];
    assert_eq!(drop_subsumed(&mut regions), 1);
    assert_eq!(ids(&regions), vec![2]);
}

#[test]
fn a_run_with_a_copy_the_longer_one_misses_stays() {
    // The third copy shares only the shorter stretch, so the longer run
    // does not account for it and both runs carry a fact of their own.
    let mut regions = vec![
        region(
            1,
            CloneClass::Type1,
            4,
            &[(0, 20, 40), (1, 120, 140), (2, 220, 240)],
        ),
        region(2, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
    ];
    assert_eq!(drop_subsumed(&mut regions), 0);
    assert_eq!(ids(&regions), vec![1, 2]);
}

#[test]
fn a_verbatim_run_inside_a_renamed_one_keeps_its_stronger_claim() {
    // "These eight statements match up to renaming, and these four of
    // them match verbatim" is two facts. Dropping the inner one would
    // report only the weaker.
    let mut regions = vec![
        region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
        region(2, CloneClass::Type2, 8, &[(0, 10, 60), (1, 110, 160)]),
    ];
    assert_eq!(drop_subsumed(&mut regions), 0);
    assert_eq!(ids(&regions), vec![1, 2]);

    // The other way round the cover claims at least as much, so it wins.
    let mut regions = vec![
        region(1, CloneClass::Type2, 4, &[(0, 20, 40), (1, 120, 140)]),
        region(2, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
    ];
    assert_eq!(drop_subsumed(&mut regions), 1);
    assert_eq!(ids(&regions), vec![2]);
}

#[test]
fn two_runs_that_cover_each_other_do_not_both_disappear() {
    let mut regions = vec![
        region(1, CloneClass::Type1, 4, &[(0, 10, 60), (1, 110, 160)]),
        region(2, CloneClass::Type1, 4, &[(0, 10, 60), (1, 110, 160)]),
    ];
    assert_eq!(drop_subsumed(&mut regions), 1);
    assert_eq!(regions.len(), 1);
}

#[test]
fn a_run_covered_only_in_the_wrong_file_stays() {
    // Same byte offsets, different file: coverage is per occurrence, and
    // an occurrence is a place in a file.
    let mut regions = vec![
        region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
        region(2, CloneClass::Type1, 8, &[(0, 10, 60), (2, 110, 160)]),
    ];
    assert_eq!(drop_subsumed(&mut regions), 0);
    assert_eq!(ids(&regions), vec![1, 2]);
}

#[test]
fn dropping_is_independent_of_the_order_the_runs_arrive_in() {
    let build = || {
        vec![
            region(1, CloneClass::Type1, 4, &[(0, 20, 40), (1, 120, 140)]),
            region(2, CloneClass::Type1, 6, &[(0, 15, 50), (1, 115, 150)]),
            region(3, CloneClass::Type1, 8, &[(0, 10, 60), (1, 110, 160)]),
        ]
    };
    let mut forward = build();
    drop_subsumed(&mut forward);
    let mut reversed: Vec<StructuralRegion> = build().into_iter().rev().collect();
    drop_subsumed(&mut reversed);
    assert_eq!(ids(&forward), vec![3]);
    assert_eq!(ids(&reversed), vec![3]);
}

#[test]
fn subsumption_index_uses_the_rarest_occurrence_before_full_confirmation() {
    let mut regions = vec![region(
        1,
        CloneClass::Type1,
        20,
        &[(0, 0, 1_000), (1, 2_000, 3_000)],
    )];
    // These regions all cover the candidate's first occurrence but none
    // covers its second one. The second occurrence leaves the one actual
    // outer region as the only candidate that needs full confirmation.
    for id in 2..=129 {
        regions.push(region(
            id,
            CloneClass::Type1,
            8,
            &[(0, 0, 1_000), (1, usize::from(id), usize::from(id) + 1)],
        ));
    }
    regions.push(region(
        250,
        CloneClass::Type1,
        4,
        &[(0, 400, 600), (1, 2_400, 2_600)],
    ));

    assert_eq!(drop_subsumed(&mut regions), 1);
    assert_eq!(regions.len(), 129);
    assert!(!ids(&regions).contains(&250));
}

fn quadratic_drop_subsumed(regions: &mut Vec<StructuralRegion>) -> usize {
    let before = regions.len();
    let mut order: Vec<usize> = (0..regions.len()).collect();
    order.sort_by_key(|&index| {
        (
            std::cmp::Reverse(regions[index].statements),
            regions[index].fingerprint,
        )
    });
    let mut dropped = vec![false; regions.len()];
    for (rank, &inner) in order.iter().enumerate() {
        if order[..rank]
            .iter()
            .any(|&outer| !dropped[outer] && covers_run(&regions[outer], &regions[inner]))
        {
            dropped[inner] = true;
        }
    }
    *regions = std::mem::take(regions)
        .into_iter()
        .zip(dropped)
        .filter_map(|(region, drop)| (!drop).then_some(region))
        .collect();
    before - regions.len()
}

#[test]
fn subsumption_index_matches_the_quadratic_oracle_on_mixed_regions() {
    let mut input = vec![region(
        1,
        CloneClass::Type1,
        32,
        &[(0, 0, 2_000), (1, 3_000, 5_000)],
    )];
    for id in 2..=64 {
        let offset = usize::from(id) * 7;
        let clone_type = match id % 3 {
            0 => CloneClass::Type1,
            1 => CloneClass::Type2,
            _ => CloneClass::Type3,
        };
        input.push(region(
            id,
            clone_type,
            4 + u32::from(id % 8),
            &[
                (0, offset, 2_000 - offset),
                (1, 3_000 + offset, 5_000 - offset),
            ],
        ));
    }
    input.extend([
        region(65, CloneClass::Type1, 8, &[(2, 0, 800), (3, 0, 800)]),
        region(66, CloneClass::Type1, 4, &[(2, 50, 750), (4, 50, 750)]),
        region(67, CloneClass::Type2, 4, &[(2, 50, 750), (3, 50, 750)]),
    ]);

    let mut indexed = input.clone();
    let mut quadratic = input;
    assert_eq!(
        drop_subsumed(&mut indexed),
        quadratic_drop_subsumed(&mut quadratic)
    );
    assert_eq!(indexed, quadratic);
}

/// A confirmed run at one alignment: `spans` gives each occurrence's file
/// and the statement it starts at, all in one block.
fn confirmed(id: u8, statements: u32, spans: &[(usize, u32)]) -> Confirmed {
    let sides: Vec<RegionSide> = spans
        .iter()
        .map(|&(file, start)| RegionSide {
            file,
            unit: 0,
            run: StatementRun {
                block: 0,
                start,
                length: statements,
            },
            // Ten bytes a statement, so ranges follow the run.
            range: ByteRange {
                start: (start as usize) * 10,
                end: (start as usize + statements as usize) * 10,
            },
        })
        .collect();
    let occurrences = sides
        .iter()
        .map(|side| occurrence(side.file, side.range.start, side.range.end))
        .collect();
    Confirmed {
        region: StructuralRegion {
            fingerprint: CloneGroupFingerprint::from_bytes([id; 16]),
            clone_type: CloneClass::Type1,
            statements,
            occurrences,
        },
        sides,
    }
}

#[test]
fn two_runs_describing_one_stretch_at_two_offsets_join() {
    // Statements 2..7 in one file match 1..6 in another, and 3..8 match
    // 2..7. That is one six-statement stretch, reported twice.
    let confirmed = vec![
        confirmed(1, 5, &[(0, 2), (1, 1)]),
        confirmed(2, 5, &[(0, 3), (1, 2)]),
    ];
    let joined = merge_adjacent(&confirmed);
    assert_eq!(joined.len(), 1);
    assert_eq!(joined[0].statements, 6);
    let starts: Vec<u32> = joined[0]
        .occurrences
        .iter()
        .map(|side| side.run.start)
        .collect();
    assert_eq!(starts, vec![2, 1]);
    assert_eq!(
        joined[0].occurrences[0].range,
        ByteRange { start: 20, end: 80 }
    );
}

#[test]
fn runs_too_far_apart_to_touch_are_two_duplications() {
    // A gap of statements neither run covers: joining would claim the
    // statements in between match, which nothing checked.
    let confirmed = vec![
        confirmed(1, 4, &[(0, 0), (1, 0)]),
        confirmed(2, 4, &[(0, 9), (1, 9)]),
    ];
    assert_eq!(merge_adjacent(&confirmed), vec![]);
}

#[test]
fn runs_that_shift_by_different_amounts_do_not_join() {
    // One side advances by one statement and the other by three, so the
    // two runs are not one stretch seen twice.
    let confirmed = vec![
        confirmed(1, 5, &[(0, 2), (1, 2)]),
        confirmed(2, 5, &[(0, 3), (1, 5)]),
    ];
    assert_eq!(merge_adjacent(&confirmed), vec![]);
}

#[test]
fn runs_with_different_occurrence_counts_do_not_join() {
    // The shorter run has a third copy, which the join would silently
    // credit with statements it does not hold.
    let confirmed = vec![
        confirmed(1, 5, &[(0, 2), (1, 1)]),
        confirmed(2, 5, &[(0, 3), (1, 2), (2, 4)]),
    ];
    assert_eq!(merge_adjacent(&confirmed), vec![]);
}

#[test]
fn runs_starting_together_are_left_to_containment() {
    let confirmed = vec![
        confirmed(1, 4, &[(0, 2), (1, 1)]),
        confirmed(2, 6, &[(0, 2), (1, 1)]),
    ];
    assert_eq!(merge_adjacent(&confirmed), vec![]);
}

#[test]
fn joining_does_not_depend_on_the_order_the_runs_arrive_in() {
    let build = || {
        vec![
            confirmed(1, 5, &[(0, 2), (1, 1)]),
            confirmed(2, 5, &[(0, 3), (1, 2)]),
            confirmed(3, 5, &[(0, 4), (1, 3)]),
        ]
    };
    let forward = merge_adjacent(&build());
    let reversed: Vec<Confirmed> = build().into_iter().rev().collect();
    assert_eq!(forward, merge_adjacent(&reversed));
    assert!(!forward.is_empty());
}

#[test]
fn runs_holding_one_content_are_one_run() {
    // Two candidates confirmed the same content in four places between them.
    // That is one duplication with four occurrences: reported apart the two
    // would carry one fingerprint, which is then no longer an identity.
    let mut dropped = Dropped::default();
    let (regions, folded) = fold_by_content(
        vec![
            confirmed(1, 4, &[(0, 0), (1, 0)]),
            confirmed(1, 4, &[(0, 10), (1, 10)]),
        ],
        &mut dropped,
    );

    assert_eq!(folded, 1);
    assert_eq!(regions.len(), 1);
    let places: Vec<(usize, ByteRange)> = regions[0]
        .occurrences
        .iter()
        .map(|occurrence| (occurrence.file, occurrence.range))
        .collect();
    assert_eq!(
        places,
        vec![
            (0, ByteRange { start: 0, end: 40 }),
            (
                0,
                ByteRange {
                    start: 100,
                    end: 140
                }
            ),
            (1, ByteRange { start: 0, end: 40 }),
            (
                1,
                ByteRange {
                    start: 100,
                    end: 140
                }
            ),
        ],
        "the occurrences of one content are collected in source order"
    );
}

#[test]
fn an_occurrence_two_candidates_both_name_is_described_once() {
    // The second candidate covers everything the first does and one place
    // more. Naming a place twice is not an overlap between two stretches of
    // source, so it is not counted as one.
    let mut dropped = Dropped::default();
    let (regions, folded) = fold_by_content(
        vec![
            confirmed(1, 4, &[(0, 0), (1, 0)]),
            confirmed(1, 4, &[(0, 0), (1, 0), (2, 0)]),
        ],
        &mut dropped,
    );

    assert_eq!(folded, 1);
    assert_eq!(regions.len(), 1);
    assert_eq!(regions[0].occurrences.len(), 3);
    assert_eq!(dropped.overlapping, 0);
}

#[test]
fn collecting_one_content_still_settles_its_overlaps() {
    // The two candidates reach into each other in the first file: those are
    // one stretch of source, and the rule that decides so within a candidate
    // decides it across two.
    let mut dropped = Dropped::default();
    let (regions, _) = fold_by_content(
        vec![
            confirmed(1, 4, &[(0, 0), (1, 0)]),
            confirmed(1, 4, &[(0, 2), (2, 0)]),
        ],
        &mut dropped,
    );

    assert_eq!(regions.len(), 1);
    assert_eq!(dropped.overlapping, 1);
    let files: Vec<usize> = regions[0]
        .occurrences
        .iter()
        .map(|occurrence| occurrence.file)
        .collect();
    assert_eq!(files, vec![0, 1, 2]);
}

#[test]
fn runs_holding_different_content_stay_apart() {
    let mut dropped = Dropped::default();
    let (regions, folded) = fold_by_content(
        vec![
            confirmed(1, 4, &[(0, 0), (1, 0)]),
            confirmed(2, 4, &[(0, 10), (1, 10)]),
        ],
        &mut dropped,
    );

    assert_eq!(folded, 0);
    assert_eq!(regions.len(), 2);
}

#[test]
fn no_two_folded_runs_share_a_fingerprint() {
    let mut dropped = Dropped::default();
    let (regions, _) = fold_by_content(
        vec![
            confirmed(1, 4, &[(0, 0), (1, 0)]),
            confirmed(1, 4, &[(0, 10), (1, 10)]),
            confirmed(2, 4, &[(0, 20), (1, 20)]),
            confirmed(2, 4, &[(0, 30), (1, 30)]),
        ],
        &mut dropped,
    );

    let mut seen = BTreeSet::new();
    for region in &regions {
        assert!(
            seen.insert(region.fingerprint),
            "a stable id names one finding"
        );
    }
    assert_eq!(regions.len(), 2);
}

#[test]
fn cross_variant_comparison_keeps_origins_and_is_order_stable() {
    let tokens = [Token {
        kind: TokenKind::Identifier,
        text: "same".into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 4,
            start_line: 1,
            start_column: 1,
        },
    }];
    let left = CrossVariantUnit {
        origin_variant: "b",
        language: Language::Cpp,
        file_path: "left.cpp",
        start_line: 2,
        end_line: 4,
        name: Some("left"),
        tokens: &tokens,
    };
    let right = CrossVariantUnit {
        origin_variant: "a",
        language: Language::Cpp,
        file_path: "right.cpp",
        start_line: 5,
        end_line: 7,
        name: Some("right"),
        tokens: &tokens,
    };
    let forward = compare_build_variants(&[left, right]).expect("two distinct build variants");
    let reverse = compare_build_variants(&[right, left]).expect("two distinct build variants");
    assert_eq!(forward, reverse);
    assert_eq!(forward.origin_variants, vec!["a", "b"]);
    assert_eq!(forward.groups.len(), 1);
    assert_eq!(forward.groups[0].members[0].origin_variant, "a");
    assert!(compare_build_variants(&[left]).is_none());

    let moved_left = CrossVariantUnit {
        file_path: "moved/left.cpp",
        start_line: 200,
        end_line: 204,
        ..left
    };
    let moved_right = CrossVariantUnit {
        file_path: "moved/right.cpp",
        start_line: 500,
        end_line: 507,
        ..right
    };
    let moved = compare_build_variants(&[moved_left, moved_right]).expect("moved comparison");
    assert_eq!(forward.groups[0].id, moved.groups[0].id);
    assert_eq!(
        forward.groups[0]
            .members
            .iter()
            .map(|member| member.id)
            .collect::<Vec<_>>(),
        moved.groups[0]
            .members
            .iter()
            .map(|member| member.id)
            .collect::<Vec<_>>()
    );
}

#[test]
fn cross_variant_group_identity_includes_the_language_class_axis() {
    let tokens = [Token {
        kind: TokenKind::Identifier,
        text: "same".into(),
        span: SourceSpan {
            start_byte: 0,
            end_byte: 4,
            start_line: 1,
            start_column: 1,
        },
    }];
    let unit = |origin_variant, language, file_path| CrossVariantUnit {
        origin_variant,
        language,
        file_path,
        start_line: 1,
        end_line: 1,
        name: Some("same"),
        tokens: &tokens,
    };
    let comparison = compare_build_variants(&[
        unit("a", Language::C, "a.c"),
        unit("b", Language::C, "b.c"),
        unit("a", Language::Cpp, "a.cpp"),
        unit("b", Language::Cpp, "b.cpp"),
    ])
    .expect("two origins in both language classes");

    assert_eq!(comparison.groups.len(), 2);
    assert_ne!(comparison.groups[0].id, comparison.groups[1].id);
}
