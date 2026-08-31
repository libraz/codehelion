use super::regions::Dropped;
use super::reporting::{PairEvidence, group_detail, group_fingerprint, verifier_calls};
use super::{
    Boilerplate, CloneClass, Confirmed, CrossVariantUnit, DirectoryPartition, RegionOccurrence,
    RegionSide, ResolvedTypes, SignatureSiblingSweepStats, StructuralConfig, StructuralRegion,
    Unit, compare_build_variants, covers_run, dominant_boilerplate, drop_subsumed, features,
    flatten_units, fold_by_content, is_allocation_api, merge_adjacent, set_jaccard, unit_evidence,
    unrepresented_pairs, view,
};
use crate::candidate::StatementRun;
use crate::conditional::{ArmPath, ArmTracker, StaticCondition};
use crate::discovery::{BuildVariant, Language, LanguageSelection};
use crate::engine::{LiteralNorm, normalize::Resolution};
use crate::frontend::{SourceSpan, Token, TokenKind, UnitKind};
use crate::grouping;
use crate::ir::{ByteRange, IR_SCHEMA_VERSION, IrNode, Shape, Signature, SyntaxIrFile};
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

    assert_eq!(set_jaccard(&first, &first), Some(1.0));
    assert_eq!(set_jaccard(&first, &second), Some(0.5));
    assert_eq!(
        set_jaccard(&empty, &empty),
        None,
        "two spans naming nothing agree about nothing"
    );
    assert_eq!(
        set_jaccard(&first, &empty),
        Some(0.0),
        "one side naming something is a comparison that was made"
    );
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
        signature: None,
        directory: None,
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
        signatures: Vec::new(),
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

fn rich_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = cohesion_file(words);
    file.roots[0].children[0].children = words
        .iter()
        .enumerate()
        .map(|(index, _)| IrNode {
            shape: Shape::ExprStmt,
            name: None,
            token_start: index,
            token_end: index + 1,
            range: ByteRange {
                start: index * 8,
                end: index * 8 + 1,
            },
            children: Vec::new(),
        })
        .collect();
    file
}

/// The same file with every token a literal, as a duplicated table of constants
/// is: nothing in it is a name two copies could share or differ in.
fn literal_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    for token in &mut file.tokens {
        token.kind = TokenKind::Literal(crate::frontend::LiteralKind::Integer);
    }
    file
}

/// Identifier agreement is evidence about names, so a comparison between spans
/// that hold no name measures nothing. Reporting the strongest possible value
/// for it would let a filter written to demand shared names admit exactly the
/// findings that have none.
#[test]
fn spans_holding_no_identifier_are_unmeasured_rather_than_in_perfect_agreement() {
    let words = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"];
    let literals = vec![literal_cohesion_file(&words), literal_cohesion_file(&words)];
    let named = vec![
        rich_cohesion_file(&words),
        rich_cohesion_file(&["1", "2", "3", "4", "5", "6", "7", "8", "9", "x"]),
    ];
    let whole_file = |file: usize| crate::structural::SourceTokenSpan::new(file, 0, words.len());

    assert_eq!(
        super::span_identifier_jaccard(&literals, whole_file(0), [whole_file(1)]),
        None
    );
    assert!(
        super::span_identifier_jaccard(&named, whole_file(0), [whole_file(1)]).is_some(),
        "spans that do name something are still measured"
    );
    assert_eq!(
        super::span_identifier_jaccard(&literals, whole_file(0), []),
        None,
        "a canonical span compared against nothing was compared to nothing"
    );

    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
    );
    let config = StructuralConfig::default();
    let feature_files: Vec<_> = literals.iter().map(features::extract).collect();
    let (units, _) = flatten_units(
        &literals,
        &variant,
        config.literals,
        &ResolvedTypes::default(),
    );
    let evidence = unit_evidence(&units, &ResolvedTypes::default());
    let edges = Vec::new();
    let detail = group_detail(
        &grouped(vec![0, 1]),
        &units,
        &literals,
        &feature_files,
        &evidence,
        &PairEvidence::index(&edges),
        &variant,
        &config,
    );

    assert_eq!(
        detail.identifier_jaccard, None,
        "a group of copies that name nothing was not measured on names"
    );
}

/// A file whose first walked unit shape covers no token, as a tree cut off at
/// a depth limit leaves one, followed by a unit that covers the file.
fn file_with_a_tokenless_unit(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    file.roots[0].name = Some("kept".into());
    file.roots.insert(
        0,
        IrNode {
            shape: Shape::Function,
            name: Some("tokenless".into()),
            token_start: words.len(),
            token_end: words.len(),
            range: ByteRange { start: 0, end: 0 },
            children: Vec::new(),
        },
    );
    file
}

/// Line numbers are 1-based, so a zero is not a position a reader can look at.
/// A unit shape covering no token has none to report, and reporting it anyway
/// would put a value in the line columns that reads like a place in the file.
#[test]
fn a_unit_shape_covering_no_token_is_not_reported_at_line_zero() {
    let words = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
    let files = vec![
        file_with_a_tokenless_unit(&words),
        rich_cohesion_file(&words),
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

    let (units, index) =
        flatten_units(&files, &variant, config.literals, &ResolvedTypes::default());

    assert_eq!(units.len(), 2, "the tokenless shape becomes no unit");
    assert_eq!(
        index.global(0, 0),
        None,
        "a candidate naming the tokenless walk position resolves to no unit"
    );
    assert_eq!(
        index.global(0, 1),
        Some(0),
        "the unit after it keeps its own global index rather than the one before"
    );
    assert_eq!(index.global(1, 0), Some(1));
    let feature_files: Vec<_> = files.iter().map(features::extract).collect();
    assert_eq!(
        feature_files[0].units[units[0].local].name.as_deref(),
        Some("kept"),
        "the recorded unit still addresses its own features"
    );

    let report = super::analyze(&files, &variant, &config);

    assert_eq!(report.units.len(), 2);
    assert!(
        report
            .units
            .iter()
            .all(|unit| unit.start_line >= 1 && unit.end_line >= 1)
    );
    assert!(
        report
            .regions
            .iter()
            .flat_map(|region| &region.occurrences)
            .all(|occurrence| occurrence.start_line >= 1 && occurrence.end_line >= 1)
    );
}

/// A file holding one closure inside one function, so that its two units
/// enclose each other and no proposal naming both is a pair.
fn file_with_a_nested_unit(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    let inner = IrNode {
        shape: Shape::Closure,
        name: Some("inner".into()),
        token_start: 1,
        token_end: words.len().min(4),
        range: ByteRange { start: 8, end: 32 },
        children: Vec::new(),
    };
    file.roots[0].children[0].children.push(inner);
    file
}

/// A candidate stage names two units; whether they are a pair is a fact about
/// the two units, not about which stage said so. Three stages proposing the
/// same two units describe one pair, and counting the rejection once per
/// proposal would report a run that considered three times as many pairs as it
/// had.
#[test]
fn one_pair_proposed_by_every_stage_is_rejected_once() {
    let words = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
    let files = vec![file_with_a_nested_unit(&words)];
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
    let (units, index) =
        flatten_units(&files, &variant, config.literals, &ResolvedTypes::default());
    assert_eq!(units.len(), 2, "one function holding one closure");

    let outer = features::UnitRef {
        file: 0,
        unit: 0,
        node_count: 1,
    };
    let inner = features::UnitRef {
        file: 0,
        unit: 1,
        node_count: 1,
    };
    let fragment = |unit: usize| crate::candidate::FragmentRef {
        file: 0,
        unit,
        start_byte: 0,
        end_byte: 8,
        extent: 1,
        run: None,
    };
    let candidates = crate::candidate::CandidateSet {
        pairs: vec![crate::candidate::CandidatePair {
            kind: features::FeatureKind::StatementWindow,
            hash: features::FeatureHash::from_bytes([0; 16]),
            a: fragment(0),
            b: fragment(1),
        }],
        stats: crate::candidate::CandidateStats::default(),
    };
    let near = crate::near_match::NearMatchSet {
        pairs: vec![crate::near_match::NearMatchPair {
            a: outer,
            b: inner,
            estimated_jaccard: 0.9,
        }],
        near_misses: Vec::new(),
        stats: crate::near_match::NearMatchStats::default(),
    };
    let skeleton = crate::control_flow::ControlFlowSet {
        pairs: vec![crate::control_flow::ControlFlowPair {
            a: outer,
            b: inner,
            hash: features::FeatureHash::from_bytes([0; 16]),
        }],
        stats: crate::control_flow::ControlFlowStats::default(),
    };

    let lifted = super::lift_to_unit_pairs(
        &candidates,
        &near,
        &skeleton,
        &units,
        &index,
        &feature_files,
        config.max_shape_divergence,
    );

    assert!(lifted.pairs.is_empty());
    assert_eq!(
        lifted.nested, 1,
        "three proposals about two units are one pair"
    );
    assert_eq!(lifted.alternatives, 0);
    assert_eq!(lifted.divergent, 0);
}

/// A unit under an arm no build compiles is not half of a clone pair, however
/// a stage proposes it. The Fast gate drops such a proposal already, and a
/// pair only one mode reports is a finding about code no build holds.
#[test]
fn a_pair_naming_an_arm_no_build_takes_is_not_proposed() {
    let words = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
    let files = vec![cohesion_file(&words), cohesion_file(&words)];
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
    let (mut units, index) =
        flatten_units(&files, &variant, config.literals, &ResolvedTypes::default());
    assert_eq!(units.len(), 2, "one function per file");

    let unit_ref = |file: usize| features::UnitRef {
        file,
        unit: 0,
        node_count: 1,
    };
    let candidates = crate::candidate::CandidateSet {
        pairs: Vec::new(),
        stats: crate::candidate::CandidateStats::default(),
    };
    let near = crate::near_match::NearMatchSet {
        pairs: vec![crate::near_match::NearMatchPair {
            a: unit_ref(0),
            b: unit_ref(1),
            estimated_jaccard: 0.9,
        }],
        near_misses: Vec::new(),
        stats: crate::near_match::NearMatchStats::default(),
    };
    let skeleton = crate::control_flow::ControlFlowSet {
        pairs: Vec::new(),
        stats: crate::control_flow::ControlFlowStats::default(),
    };

    let mut dead = ArmTracker::default();
    dead.begin(StaticCondition::False);
    units[0].arms = dead.current();
    let lifted = super::lift_to_unit_pairs(
        &candidates,
        &near,
        &skeleton,
        &units,
        &index,
        &feature_files,
        config.max_shape_divergence,
    );
    assert!(lifted.pairs.is_empty(), "the pair reaches no judge");
    assert_eq!(lifted.alternatives, 1, "and the funnel says why");
    assert_eq!(lifted.nested, 0);
    assert_eq!(lifted.divergent, 0);

    units[0].arms = ArmPath::default();
    let reachable = super::lift_to_unit_pairs(
        &candidates,
        &near,
        &skeleton,
        &units,
        &index,
        &feature_files,
        config.max_shape_divergence,
    );
    assert_eq!(
        reachable.pairs.len(),
        1,
        "the same two units outside any conditional are a pair, so the drop is about the arm"
    );
}

fn divergent_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    for child in &mut file.roots[0].children[0].children {
        child.shape = Shape::Return;
    }
    file
}

fn second_divergent_cohesion_file(words: &[&str]) -> SyntaxIrFile {
    let mut file = rich_cohesion_file(words);
    for child in &mut file.roots[0].children[0].children {
        child.shape = Shape::Break;
    }
    file
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
    let edges = vec![
        cohesion_edge(0, 1, canonical_to_first),
        cohesion_edge(0, 2, canonical_to_second),
        cohesion_edge(1, 2, weakest_pair),
    ];
    let pairs = PairEvidence::index(&edges);
    verifier_calls::reset();
    let detail = group_detail(
        &group,
        &units,
        &files,
        &feature_files,
        &evidence,
        &pairs,
        &variant,
        &config,
    );

    assert_eq!(detail.cohesion_breakdown, weakest_pair);
    assert!((detail.cohesion_breakdown.composite - group.min_pairwise).abs() < f64::EPSILON);
    assert_eq!(
        detail.member_breakdowns[1..],
        [canonical_to_first, canonical_to_second]
    );
    // Only the medoid's self-comparison has no verified pair to read.
    assert_eq!(verifier_calls::count(), 1);
}

fn cohesion_edge(a: usize, b: usize, breakdown: SimilarityBreakdown) -> grouping::SimilarityEdge {
    grouping::SimilarityEdge {
        a,
        b,
        similarity: breakdown.composite,
        breakdown: Some(breakdown),
        class: CloneClass::Type3,
        confidence: Confidence::High,
    }
}

#[test]
fn group_cohesion_evidence_falls_back_to_one_measurement_for_a_scalar_edge() {
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
    let weakest = crate::verify::verify(
        &view(1, &units, &files, &feature_files, &evidence),
        &view(2, &units, &files, &feature_files, &evidence),
        &config.verify,
    )
    .breakdown;

    let group = grouping::StructuralGroup {
        clone_type: CloneClass::Type3,
        confidence: Confidence::High,
        canonical: 0,
        medoid_similarities: vec![1.0, 0.99, 0.99],
        min_pairwise: weakest.composite,
        members: vec![0, 1, 2],
    };
    // A caller that carried scalar similarities without the verifier evidence:
    // the weakest pair is still named by the similarities, and only that pair
    // is measured again.
    let edges: Vec<grouping::SimilarityEdge> =
        [(0, 1, 0.99), (0, 2, 0.99), (1, 2, weakest.composite)]
            .into_iter()
            .map(|(a, b, similarity)| grouping::SimilarityEdge {
                a,
                b,
                similarity,
                breakdown: None,
                class: CloneClass::Type3,
                confidence: Confidence::High,
            })
            .collect();
    let pairs = PairEvidence::index(&edges);
    let detail = group_detail(
        &group,
        &units,
        &files,
        &feature_files,
        &evidence,
        &pairs,
        &variant,
        &config,
    );

    assert_eq!(detail.cohesion_breakdown, weakest);
}

#[test]
fn group_details_agree_with_an_exhaustive_pairwise_reading() {
    let mut files = Vec::new();
    for shape in 0..3 {
        for copy in 0..6 {
            let mut words: Vec<String> = (0..24).map(|index| format!("word{index}")).collect();
            words[shape] = format!("shape{shape}");
            words[23] = format!("copy{copy}");
            let borrowed: Vec<&str> = words.iter().map(String::as_str).collect();
            files.push(rich_cohesion_file(&borrowed));
        }
    }
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
    );
    let config = StructuralConfig {
        min_clone_tokens: 1,
        ..StructuralConfig::default()
    };
    verifier_calls::reset();
    let report = crate::structural::analyze(&files, &variant, &config);
    let measured = verifier_calls::count();

    let feature_files: Vec<_> = files.iter().map(features::extract).collect();
    let (units, _) = flatten_units(&files, &variant, config.literals, &ResolvedTypes::default());
    let evidence = unit_evidence(&units, &ResolvedTypes::default());
    let breakdown_of = |a: usize, b: usize| {
        crate::verify::verify(
            &view(a, &units, &files, &feature_files, &evidence),
            &view(b, &units, &files, &feature_files, &evidence),
            &config.verify,
        )
        .breakdown
    };

    // A group holding more than two members is what makes the pairwise reading
    // worth checking at all.
    assert!(
        report
            .groups
            .groups
            .iter()
            .any(|group| group.members.len() > 2)
    );
    for (group, detail) in report.groups.groups.iter().zip(&report.details) {
        let expected_members: Vec<SimilarityBreakdown> = group
            .members
            .iter()
            .map(|&member| breakdown_of(group.canonical, member))
            .collect();
        assert_eq!(detail.member_breakdowns, expected_members);

        let expected_cohesion = group
            .members
            .iter()
            .enumerate()
            .flat_map(|(left, &a)| group.members[left + 1..].iter().map(move |&b| (a, b)))
            .map(|(a, b)| breakdown_of(a, b))
            .min_by(|left, right| left.composite.total_cmp(&right.composite));
        assert_eq!(Some(detail.cohesion_breakdown), expected_cohesion);
        assert!((detail.cohesion_breakdown.composite - group.min_pairwise).abs() < f64::EPSILON);
    }

    // Reporting measures a pair only where no verified edge can answer: the
    // medoid against itself, once per group.
    assert!(
        measured <= report.groups.groups.len(),
        "reporting measured {measured} pairs for {} groups",
        report.groups.groups.len()
    );
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
            signatures: Vec::new(),
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
            signatures: Vec::new(),
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
            signatures: Vec::new(),
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
fn an_occurrence_that_named_no_tokens_did_not_disagree_with_anything() {
    // Both sides name a file outside the analysed slice, so neither one's
    // content was ever established. Counting them as content that failed to
    // agree would point an investigation at the comparison instead of at the
    // range that resolved to nothing.
    let side = |file: usize| RegionSide {
        file,
        unit: 0,
        run: StatementRun {
            block: 0,
            start: 0,
            length: 2,
        },
        range: ByteRange { start: 0, end: 8 },
    };
    let candidate = crate::maximal::SharedRegion {
        occurrences: vec![side(0), side(1)],
        statements: 2,
    };

    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Cpp,
    );
    let (confirmed, dropped) = super::confirm_regions(
        std::slice::from_ref(&candidate),
        &[],
        &super::units::UnitIndex::dense(Vec::new()),
        &variant,
        LiteralNorm::default(),
    );

    assert!(confirmed.is_empty());
    assert_eq!(dropped.unresolved, 2);
    assert_eq!(
        dropped.singletons, 0,
        "unshared content is a claim about content that was read"
    );
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

#[test]
fn signature_context_is_cross_file_scoped_and_cardinality_safe() {
    let mut files = vec![
        rich_cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
        rich_cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]),
        divergent_cohesion_file(&["a", "b", "c", "d", "e", "f", "g", "h", "i", "x"]),
        second_divergent_cohesion_file(&["q", "r", "s", "t", "u", "v", "w", "x", "y", "z"]),
    ];
    let signature = Signature::new(Language::Rust, "rust|params=[]|return=()");
    for file in &mut files {
        file.signatures = vec![(file.roots[0].range, signature.clone())];
    }
    let config = StructuralConfig {
        min_clone_tokens: 1,
        ..StructuralConfig::default()
    };
    let report = crate::structural::analyze_with_context(
        &files,
        &BuildVariant::structural(
            LanguageSelection {
                rust: true,
                c: false,
                cpp: false,
            },
            Language::Rust,
        ),
        &config,
        &[
            DirectoryPartition::new(0),
            DirectoryPartition::new(0),
            DirectoryPartition::new(0),
            DirectoryPartition::new(1),
        ],
    );
    assert_eq!(report.stats.signature_siblings.groups_considered, 1);
    assert_eq!(report.stats.signature_siblings.eligible_candidates, 1);
    assert_eq!(report.stats.signature_siblings.candidates_examined, 1);
    assert_eq!(report.stats.signature_siblings.accepted, 1);
    assert_eq!(report.siblings.len(), 1);
    assert_eq!(report.siblings[0].siblings.len(), 1);
    assert_eq!(report.siblings[0].siblings[0].unit, 2);
    assert_eq!(
        report.siblings[0].siblings[0].basis,
        super::SiblingBasis::Signature
    );

    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Rust,
    );
    let legacy = crate::structural::analyze(&files, &variant, &config);
    assert_eq!(
        legacy.stats.signature_siblings,
        SignatureSiblingSweepStats::default()
    );
    assert!(legacy.siblings.is_empty());
    assert_eq!(report.units, legacy.units);
    assert_eq!(report.groups, legacy.groups);
    assert_eq!(report.regions, legacy.regions);
    assert_eq!(report.details, legacy.details);
    assert_eq!(report.unrepresented, legacy.unrepresented);
    assert_eq!(report.near_misses, legacy.near_misses);
    assert_eq!(report.stats.siblings, legacy.stats.siblings);
    let mut primary_stats = report.stats;
    primary_stats.signature_siblings = SignatureSiblingSweepStats::default();
    assert_eq!(primary_stats, legacy.stats);

    let mismatch = crate::structural::analyze_with_context(
        &files,
        &variant,
        &config,
        &[DirectoryPartition::new(0)],
    );
    assert_eq!(mismatch, legacy);
}

/// Two crossings of one pair of contents can agree on similarity and still say
/// different things about it. Which of them the entry then reports has to
/// follow the judgements themselves: a fold that kept whichever the caller
/// listed first would give the same corpus two different findings depending on
/// the order the crossings were handed over, and the evidence a report shows
/// would stop being a property of the code.
#[test]
fn a_folded_pair_reports_the_same_crossing_whichever_order_it_is_given() {
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
            signatures: Vec::new(),
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
    // The two crossings score identically and are believed differently.
    let confident = grouping::SimilarityEdge {
        a: 0,
        b: 2,
        similarity: 0.85,
        breakdown: Some(SimilarityBreakdown {
            lexical: 0.90,
            structural: 0.80,
            control_flow: Some(0.85),
            type_similarity: None,
            api: Some(0.85),
            composite: 0.85,
        }),
        class: CloneClass::Type3,
        confidence: Confidence::High,
    };
    let doubtful = grouping::SimilarityEdge {
        a: 1,
        b: 3,
        similarity: 0.85,
        breakdown: Some(SimilarityBreakdown {
            lexical: 0.80,
            structural: 0.90,
            control_flow: Some(0.85),
            type_similarity: None,
            api: Some(0.85),
            composite: 0.85,
        }),
        class: CloneClass::Type3,
        confidence: Confidence::Low,
    };
    let variant = BuildVariant::structural(
        LanguageSelection {
            rust: true,
            c: false,
            cpp: false,
        },
        Language::Cpp,
    );
    let carried = |edges: &[grouping::SimilarityEdge]| {
        let groups = grouping::group(
            &grouping_units,
            edges,
            &grouping::GroupingConfig {
                medoid_min_similarity: 0.98,
                min_pairwise_similarity: 0.98,
                ..grouping::GroupingConfig::default()
            },
        );
        unrepresented_pairs(edges, &groups, &units, &files, &variant).0
    };

    let listed = carried(&[confident, doubtful]);
    let reversed = carried(&[doubtful, confident]);

    assert_eq!(listed.len(), 1);
    assert_eq!(listed, reversed);
    // The entry speaks for every crossing of both contents, so it reports the
    // one that says the least about them.
    assert_eq!(listed[0].confidence, Confidence::Low);
    assert_eq!(listed[0].breakdown, doubtful.breakdown);
}
