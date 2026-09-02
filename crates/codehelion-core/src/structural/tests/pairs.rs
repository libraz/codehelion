//! Lifting candidate proposals to unit pairs, and the pairs left
//! unrepresented by any group.

use super::*;

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

    let lifted = crate::structural::lift_to_unit_pairs(
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
    let lifted = crate::structural::lift_to_unit_pairs(
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
    let reachable = crate::structural::lift_to_unit_pairs(
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
