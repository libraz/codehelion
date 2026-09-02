//! Group fingerprints, group detail and the shapes a group is labelled with.

use super::*;

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
        crate::structural::span_identifier_jaccard(&literals, whole_file(0), [whole_file(1)]),
        None
    );
    assert!(
        crate::structural::span_identifier_jaccard(&named, whole_file(0), [whole_file(1)])
            .is_some(),
        "spans that do name something are still measured"
    );
    assert_eq!(
        crate::structural::span_identifier_jaccard(&literals, whole_file(0), []),
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
