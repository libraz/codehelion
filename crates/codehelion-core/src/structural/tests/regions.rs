//! Structural regions: subsumption, adjacency joining and content folding.

use super::*;

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
    let (confirmed, dropped) = crate::structural::confirm_regions(
        std::slice::from_ref(&candidate),
        &[],
        &crate::structural::units::UnitIndex::dense(Vec::new()),
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
