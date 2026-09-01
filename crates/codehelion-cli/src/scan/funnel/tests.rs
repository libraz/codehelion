//! What the shared funnel builders owe every statistic they are handed.

use codehelion_core::engine::EngineStats;

use super::{as_u64, fast};
use crate::report::{FunnelCause, FunnelStage};

/// Where the report carries one engine statistic.
#[derive(Debug)]
enum Surface {
    /// The Fast funnel states it, as a stage value or as a drop.
    Funnel,
    /// Another part of the report states it, for the stated reason.
    Elsewhere(&'static str),
}

/// One statistic and the surface that has to carry it.
#[derive(Debug)]
struct Statistic {
    name: &'static str,
    value: u64,
    surface: Surface,
}

/// Every statistic the engine keeps, paired with the surface that carries it.
///
/// Exhaustively destructured with no rest pattern, and every binding is moved
/// into the returned list, so a counter added to [`EngineStats`] stops this
/// compiling until somebody has said where a reader meets it. That is the same
/// discipline the builders themselves are held to; stating it again here is
/// what catches a counter bound with a "not shown" reason nobody checked.
fn surfaces(stats: &EngineStats) -> Vec<Statistic> {
    let EngineStats {
        files,
        tokens,
        raw_fingerprints,
        raw_distinct,
        stop_fingerprints,
        stop_postings,
        fragments,
        control_headers_over_limit,
        bodies_over_nesting_limit,
        fragment_classes,
        class_cap_dropped,
        seed_candidates,
        raw_pairs_available,
        fragment_candidates,
        fragment_pairs_available,
        pairs,
        restated_pairs,
        hash_collisions,
        pair_budget_exhausted,
        conditional_pairs,
        subsumed_groups,
    } = stats;
    let shown = |name, value: usize| Statistic {
        name,
        value: as_u64(value),
        surface: Surface::Funnel,
    };
    let elsewhere = |name, value: usize, reason| Statistic {
        name,
        value: as_u64(value),
        surface: Surface::Elsewhere(reason),
    };
    vec![
        elsewhere(
            "files",
            *files,
            "the summary's analysed-file counts, read off the same lexed set",
        ),
        shown("tokens", *tokens),
        shown("raw_fingerprints", *raw_fingerprints),
        shown("raw_distinct", *raw_distinct),
        shown("stop_fingerprints", *stop_fingerprints),
        shown("stop_postings", *stop_postings),
        shown("fragments", *fragments),
        shown("control_headers_over_limit", *control_headers_over_limit),
        shown("bodies_over_nesting_limit", *bodies_over_nesting_limit),
        shown("fragment_classes", *fragment_classes),
        shown("class_cap_dropped", *class_cap_dropped),
        shown("seed_candidates", *seed_candidates),
        shown("raw_pairs_available", *raw_pairs_available),
        shown("fragment_candidates", *fragment_candidates),
        shown("fragment_pairs_available", *fragment_pairs_available),
        shown("pairs", *pairs),
        shown("restated_pairs", *restated_pairs),
        shown("hash_collisions", *hash_collisions),
        elsewhere(
            "pair_budget_exhausted",
            usize::from(*pair_budget_exhausted),
            "the summary's own pair-budget field; the funnel says what it cost",
        ),
        shown("conditional_pairs", *conditional_pairs),
        shown("subsumed_groups", *subsumed_groups),
    ]
}

/// A run in which every counter holds a value no other counter holds, so a
/// number found in the funnel names exactly one statistic.
fn distinct_counts() -> EngineStats {
    EngineStats {
        files: 101,
        tokens: 102,
        raw_fingerprints: 103,
        raw_distinct: 104,
        stop_fingerprints: 105,
        stop_postings: 106,
        fragments: 107,
        control_headers_over_limit: 108,
        bodies_over_nesting_limit: 109,
        fragment_classes: 110,
        class_cap_dropped: 111,
        seed_candidates: 112,
        raw_pairs_available: 113,
        fragment_candidates: 114,
        fragment_pairs_available: 115,
        pairs: 116,
        restated_pairs: 117,
        hash_collisions: 118,
        pair_budget_exhausted: true,
        conditional_pairs: 119,
        subsumed_groups: 120,
    }
}

/// The same run with the three counters that are subtracted from another
/// counter set to nothing.
///
/// Three stages state a population as the difference between two counters, so
/// in one run only one of each pair can appear as its own number. Reading both
/// runs is what lets every counter be checked without asserting on arithmetic
/// the builder is free to change.
fn with_subtrahends_cleared(stats: &EngineStats) -> EngineStats {
    EngineStats {
        stop_fingerprints: 0,
        seed_candidates: 0,
        fragment_candidates: 0,
        ..stats.clone()
    }
}

/// Every number a funnel states, whether passed on or dropped.
fn stated_numbers(funnel: &[FunnelStage]) -> Vec<u64> {
    funnel
        .iter()
        .flat_map(|stage| {
            std::iter::once(stage.passed).chain(stage.dropped.iter().map(|drop| drop.count))
        })
        .collect()
}

/// A statistic the engine computes on every run and the report never states
/// is work spent to produce a number nobody can read. Each one either reaches
/// the funnel or names the surface that carries it instead.
#[test]
fn every_engine_statistic_reaches_a_report_surface() {
    let counts = distinct_counts();
    let mut stated = stated_numbers(&fast(&counts, 121));
    stated.extend(stated_numbers(&fast(
        &with_subtrahends_cleared(&counts),
        121,
    )));

    for statistic in surfaces(&counts) {
        match statistic.surface {
            Surface::Funnel => assert!(
                stated.contains(&statistic.value),
                "{} is computed on every run and reaches no funnel stage",
                statistic.name,
            ),
            // Named rather than skipped: the reason is the whole point of the
            // entry, and an empty one is how a counter stops being reported
            // without anybody deciding that.
            Surface::Elsewhere(reason) => assert!(
                !reason.is_empty(),
                "{} claims another surface without naming it",
                statistic.name,
            ),
        }
    }
}

/// The nesting ceiling fires inside files the run read in full, and a Fast
/// report has to say so: without it a tree whose duplication sits below the
/// extraction depth reads as a tree with no duplication in it.
#[test]
fn the_fast_funnel_states_what_the_nesting_ceiling_left_uncut() {
    let counts = EngineStats {
        fragments: 4,
        bodies_over_nesting_limit: 9,
        ..EngineStats::default()
    };

    let funnel = fast(&counts, 0);
    let fragments = funnel
        .iter()
        .find(|stage| stage.stage == "fragments")
        .expect("the fragment cut is a stage of the Fast funnel");
    let dropped = fragments
        .dropped
        .iter()
        .find(|drop| drop.cause == FunnelCause::NestingLimit.name())
        .expect("the nesting ceiling is stated where the cut happened");
    assert_eq!(dropped.count, 9);
}

/// A restatement is a pair the run found and declined to state twice. Left
/// unsaid, the verified count is short of what the two passes proposed and
/// nothing on the report accounts for the difference.
#[test]
fn the_fast_funnel_states_the_pairs_a_wider_pair_already_covered() {
    let counts = EngineStats {
        pairs: 5,
        restated_pairs: 11,
        ..EngineStats::default()
    };

    let funnel = fast(&counts, 0);
    let verified = funnel
        .iter()
        .find(|stage| stage.stage == "verified pairs")
        .expect("verification is a stage of the Fast funnel");
    let dropped = verified
        .dropped
        .iter()
        .find(|drop| drop.cause == FunnelCause::AWiderPairSaysItAlready.name())
        .expect("a folded restatement is stated where the pair was dropped");
    assert_eq!(dropped.count, 11);
}

/// One cause reading as the beginning of another makes two reasons look like
/// one reason written twice, and a reader cannot tell which number to act on.
#[test]
fn no_funnel_cause_reads_as_the_beginning_of_another() {
    for cause in FunnelCause::all() {
        for other in FunnelCause::all() {
            assert!(
                cause == other || !other.name().starts_with(cause.name()),
                "{} reads as the beginning of {}",
                cause.name(),
                other.name(),
            );
        }
    }
}

/// The stored spelling of every cause resolves back to the cause, so the
/// predicates that qualify a report read the vocabulary its producers wrote.
#[test]
fn every_cause_resolves_from_the_name_it_is_stored_under() {
    for cause in FunnelCause::all() {
        assert_eq!(FunnelCause::from_name(cause.name()), Some(*cause));
    }
    assert_eq!(FunnelCause::from_name("no_such_cause"), None);
}
