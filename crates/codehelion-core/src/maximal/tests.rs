use super::*;
use crate::candidate::FragmentRef;
use crate::features::FeatureHash;

/// A run shorter than every indexed window never reaches this stage, so a
/// floor below the shortest one would be a setting with nothing to apply
/// to. Stated here because the derivation reads as arithmetic otherwise.
#[test]
fn the_floor_is_the_shortest_run_the_seed_layer_can_offer() {
    let shortest = crate::features::WINDOW_LENGTHS
        .iter()
        .copied()
        .min()
        .expect("windows are indexed at some length");
    assert_eq!(usize::try_from(DEFAULT_MIN_STATEMENTS).unwrap(), shortest);
}

/// A window seed at a statement offset, with byte anchors derived from the
/// offset so ranges stay ordered and non-overlapping between statements.
fn window(file: usize, unit: usize, block: u32, start: u32, length: u32) -> FragmentRef {
    FragmentRef {
        file,
        unit,
        start_byte: usize::try_from(start).unwrap() * 10,
        end_byte: usize::try_from(start + length).unwrap() * 10,
        extent: length,
        run: Some(StatementRun {
            block,
            start,
            length,
        }),
    }
}

fn seed(a: FragmentRef, b: FragmentRef) -> CandidatePair {
    CandidatePair {
        kind: FeatureKind::StatementWindow,
        hash: FeatureHash::from_bytes([1; 16]),
        a,
        b,
    }
}

fn ranged_window(
    file: usize,
    unit: usize,
    block: u32,
    start: u32,
    length: u32,
    range: ByteRange,
) -> FragmentRef {
    let mut fragment = window(file, unit, block, start, length);
    fragment.start_byte = range.start;
    fragment.end_byte = range.end;
    fragment
}

#[test]
fn overlapping_seeds_fold_into_one_run() {
    // Three stride-1 windows of length four covering statements 0..6 in
    // one unit and 2..8 in the other.
    let pairs: Vec<CandidatePair> = (0..3)
        .map(|i| seed(window(0, 0, 0, i, 4), window(1, 0, 0, i + 2, 4)))
        .collect();
    let set = consolidate(&pairs, &MaximalConfig::default());

    assert_eq!(set.regions.len(), 1);
    let region = set.regions[0];
    assert_eq!(region.a.run.start, 0);
    assert_eq!(region.a.run.length, 6);
    assert_eq!(region.b.run.start, 2);
    assert_eq!(region.b.run.length, 6);
    assert_eq!(region.a.range, ByteRange { start: 0, end: 60 });
    assert_eq!(region.b.range, ByteRange { start: 20, end: 80 });
    assert_eq!(region.seeds, 3);
    assert_eq!(set.stats.seeds, 3);
    assert_eq!(set.stats.regions, 1);
}

#[test]
fn a_gap_between_seeds_leaves_two_runs() {
    // Statements 0..4 and 8..12 match; 4..8 does not. Bridging the gap
    // would claim an exact match over statements the seeds never covered.
    let pairs = vec![
        seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
        seed(window(0, 0, 0, 8, 4), window(1, 0, 0, 8, 4)),
    ];
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.regions.len(), 2);
    assert!(set.regions.iter().all(|region| region.a.run.length == 4));
}

#[test]
fn seeds_at_different_alignments_stay_apart() {
    // The same statements on side a match two different stretches on side
    // b. Those are two shared runs, not one long one.
    let pairs = vec![
        seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
        seed(window(0, 0, 0, 1, 4), window(1, 0, 0, 9, 4)),
    ];
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.regions.len(), 2);
    assert!(set.regions.iter().all(|region| region.seeds == 1));
}

#[test]
fn a_run_contained_in_a_longer_one_is_absorbed() {
    // A length-8 match and a length-4 match inside it, at the same
    // alignment but in different blocks, so the fold cannot merge them.
    let pairs = vec![
        seed(window(0, 0, 0, 0, 8), window(1, 0, 0, 0, 8)),
        seed(window(0, 0, 1, 2, 4), window(1, 0, 1, 2, 4)),
    ];
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.regions.len(), 1);
    assert_eq!(set.regions[0].a.run.length, 8);
    assert_eq!(set.stats.folded, 2);
    assert_eq!(set.stats.absorbed, 1);
}

#[test]
fn range_index_absorbs_a_large_nested_bucket_without_crossing_spans() {
    let outer = seed(
        ranged_window(
            0,
            0,
            0,
            0,
            4,
            ByteRange {
                start: 0,
                end: 4_000,
            },
        ),
        ranged_window(
            1,
            0,
            0,
            0,
            4,
            ByteRange {
                start: 8_000,
                end: 12_000,
            },
        ),
    );
    let mut pairs = vec![outer];
    for block in 1..=256 {
        let offset = usize::try_from(block).unwrap();
        pairs.push(seed(
            ranged_window(
                0,
                0,
                block,
                0,
                4,
                ByteRange {
                    start: offset,
                    end: 4_000 - offset,
                },
            ),
            ranged_window(
                1,
                0,
                block,
                0,
                4,
                ByteRange {
                    start: 8_000 + offset,
                    end: 12_000 - offset,
                },
            ),
        ));
    }
    // This has an earlier first span but an unrelated second span, so a
    // one-dimensional range index would incorrectly drop it.
    pairs.push(seed(
        ranged_window(0, 0, 300, 0, 4, ByteRange { start: 10, end: 20 }),
        ranged_window(1, 0, 300, 0, 4, ByteRange { start: 10, end: 20 }),
    ));

    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.regions.len(), 2);
    assert_eq!(set.stats.absorbed, 256);
    assert!(
        set.regions
            .iter()
            .any(|region| region.b.range == ByteRange { start: 10, end: 20 })
    );
}

#[test]
fn a_run_matching_a_shifted_copy_of_itself_is_dropped() {
    // One block of repeated statements: window 0..4 equals window 1..5.
    // Reporting that as two instances would double-count one stretch.
    let pairs = vec![seed(window(0, 0, 0, 0, 4), window(0, 0, 0, 1, 4))];
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert!(set.regions.is_empty());
    assert_eq!(set.stats.self_overlapping, 1);
}

#[test]
fn two_runs_in_one_unit_that_do_not_touch_are_kept() {
    let pairs = vec![seed(window(0, 0, 0, 0, 4), window(0, 0, 1, 20, 4))];
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.regions.len(), 1);
    assert_eq!(set.stats.self_overlapping, 0);
}

/// The side a window seed describes, for the adjacency questions.
fn side(unit: usize, block: u32, start: u32, length: u32) -> RegionSide {
    RegionSide {
        file: 0,
        unit,
        run: StatementRun {
            block,
            start,
            length,
        },
        range: ByteRange {
            start: usize::try_from(start).unwrap() * 10,
            end: usize::try_from(start + length).unwrap() * 10,
        },
    }
}

#[test]
fn a_run_that_continues_another_tiles_one_stretch() {
    let first = side(0, 0, 0, 4);
    assert!(adjoins(&first, &side(0, 0, 4, 4)), "end to end, in order");
    assert!(adjoins(&side(0, 0, 4, 4), &first), "and in either order");

    // One statement between them makes two sites, not one stretch.
    assert!(!adjoins(&first, &side(0, 0, 5, 4)));
    // A different block is a different stretch however the indices line up.
    assert!(!adjoins(&first, &side(0, 1, 4, 4)));
    // And two units are two sites however the file lays them out.
    assert!(!adjoins(&first, &side(1, 0, 4, 4)));
}

#[test]
fn a_seed_whose_sides_cover_unequal_code_is_dropped() {
    // Same four statement summaries, but one side spans three times the
    // source: a loop with a long body summarises like a loop with a short
    // one, and the size gap is what gives that away.
    let mut a = window(0, 0, 0, 0, 4);
    let mut b = window(1, 0, 0, 0, 4);
    a.end_byte = a.start_byte + 100;
    b.end_byte = b.start_byte + 300;
    let set = consolidate(&[seed(a, b)], &MaximalConfig::default());
    assert!(set.regions.is_empty());
    assert_eq!(set.stats.seeds, 1);
    assert_eq!(set.stats.divergent_extent, 1);

    // The gate is a configured ratio, not a fixed rule.
    let lenient = MaximalConfig {
        max_extent_ratio: 4.0,
        ..MaximalConfig::default()
    };
    assert_eq!(consolidate(&[seed(a, b)], &lenient).regions.len(), 1);
}

#[test]
fn the_minimum_length_drops_short_runs_and_counts_them() {
    let pairs = vec![seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4))];
    let config = MaximalConfig {
        min_statements: 5,
        ..MaximalConfig::default()
    };
    let set = consolidate(&pairs, &config);
    assert!(set.regions.is_empty());
    assert_eq!(set.stats.below_minimum, 1);
}

#[test]
fn subtree_seeds_do_not_enter_the_fold() {
    let mut pair = seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4));
    pair.kind = FeatureKind::Subtree;
    pair.a.run = None;
    pair.b.run = None;
    let set = consolidate(&[pair], &MaximalConfig::default());
    assert!(set.regions.is_empty());
    assert_eq!(set.stats.seeds, 0);
}

#[test]
fn three_copies_of_one_run_are_one_shared_region_not_three_pairs() {
    // Files 0, 1 and 2 hold the same four statements. Pairwise that is
    // three matches describing one duplication.
    let mut pairs = Vec::new();
    for a in 0..3usize {
        for b in a + 1..3 {
            pairs.push(seed(window(a, 0, 0, 0, 4), window(b, 0, 0, 0, 4)));
        }
    }
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.regions.len(), 3);
    assert_eq!(set.shared.len(), 1);
    assert_eq!(set.stats.shared, 1);
    let shared = &set.shared[0];
    assert_eq!(shared.statements, 4);
    let files: Vec<usize> = shared.occurrences.iter().map(|side| side.file).collect();
    assert_eq!(files, vec![0, 1, 2]);
}

#[test]
fn two_unrelated_duplications_stay_separate() {
    let pairs = vec![
        seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
        seed(window(2, 0, 0, 8, 4), window(3, 0, 0, 8, 4)),
    ];
    let set = consolidate(&pairs, &MaximalConfig::default());
    assert_eq!(set.shared.len(), 2);
    assert!(
        set.shared
            .iter()
            .all(|region| region.occurrences.len() == 2)
    );
}

#[test]
fn an_occurrence_matched_at_two_extents_belongs_to_both_sets() {
    // File 0 shares six statements with file 1 and only the first four
    // with file 2. Those are two duplications of different sizes, and
    // merging them would claim file 2 holds all six.
    let pairs = vec![
        seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
        seed(window(0, 0, 0, 2, 4), window(1, 0, 0, 2, 4)),
        seed(window(0, 0, 1, 0, 4), window(2, 0, 0, 0, 4)),
    ];
    let set = consolidate(&pairs, &MaximalConfig::default());
    let mut sizes: Vec<u32> = set.shared.iter().map(|region| region.statements).collect();
    sizes.sort_unstable();
    assert_eq!(sizes, vec![4, 6]);
    assert!(
        set.shared
            .iter()
            .all(|region| region.occurrences.len() == 2)
    );
}

#[test]
fn folding_does_not_depend_on_seed_order() {
    let forward = vec![
        seed(window(0, 0, 0, 0, 4), window(1, 0, 0, 0, 4)),
        seed(window(0, 0, 0, 1, 4), window(1, 0, 0, 1, 4)),
        seed(window(0, 0, 0, 2, 4), window(1, 0, 0, 2, 4)),
    ];
    let mut backward = forward.clone();
    backward.reverse();
    assert_eq!(
        consolidate(&forward, &MaximalConfig::default()),
        consolidate(&backward, &MaximalConfig::default())
    );
}
