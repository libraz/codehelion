//! Matching two results of one tree that share no identifier.
//!
//! Improving normalization, a frontend or the fingerprint schema moves every
//! stable id at once. The finding is the same duplication in the same place,
//! under a name nothing recorded before it can spell — so a baseline stops
//! suppressing, a history restarts, and the release that improved the detector
//! reads like a tree that was rewritten overnight.
//!
//! # Why the match is on place
//!
//! The ordinary comparison in [`codehelion_core::lineage`] connects groups by
//! member *content* fingerprints, which is right when the rules held still and
//! the code moved. Here the opposite happened: the code did not move at all
//! and the rules did, so content ids moved with everything else and there is
//! nothing to compare. What survives is where each occurrence sits. The same
//! text read twice puts the same duplication in the same file, in the same
//! unit, between the same lines.
//!
//! That only holds if the two runs read the same text, which is why the caller
//! must establish it before asking. A migration across two different trees
//! would be answering "what changed in the code" with a mechanism built for
//! "what changed in the rules", and the two answers are indistinguishable
//! afterwards.
//!
//! # What is deliberately not stretched
//!
//! Placements are matched exactly — same file, same unit, same line span. A
//! normalization change that moves where a duplicated stretch begins produces
//! a finding at a place nothing stood before, and it is reported as one the
//! migration could not carry rather than paired with the nearest neighbour.
//! Guessing here would silently re-point a suppression at a region nobody
//! judged, which is the one outcome worth more than the entries it saves.
//!
//! The connection floor is [`LINEAGE_MIN_OVERLAP`], the same fraction the
//! ordinary comparison uses and for the same reason: below half of the smaller
//! group, calling two groups the same duplication is a guess.

use std::collections::{BTreeMap, BTreeSet};

use codehelion_core::lineage::LINEAGE_MIN_OVERLAP;
use codehelion_store::query::{StoredGroup, StoredMember};

/// Where one occurrence sits, which is what two runs of one tree still agree
/// on after every identifier has moved.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Placement {
    /// Path relative to the scan root.
    file: String,
    /// Name of the enclosing unit, when the occurrence has one.
    unit: Option<String>,
    /// 1-based first line.
    start_line: i64,
    /// 1-based last line.
    end_line: i64,
}

impl Placement {
    fn of(member: &StoredMember) -> Self {
        Self {
            file: member.file_path.clone(),
            unit: member.unit_name.clone(),
            start_line: member.start_line.unwrap_or(0),
            end_line: member.end_line.unwrap_or(0),
        }
    }
}

/// One group of the earlier run and the group of the later one standing where
/// it stood.
#[derive(Debug, Clone, PartialEq)]
pub struct Carried {
    /// Hex group fingerprint before the rule change.
    pub from: String,
    /// Hex group fingerprint after it.
    pub to: String,
    /// The later group's finding ids, in the order it recorded them.
    pub findings: Vec<String>,
    /// Occurrences both groups place identically.
    pub shared: usize,
    /// Shared placements as a fraction of the smaller group.
    pub overlap: f64,
}

/// One group of the later run standing in for a group of the earlier one, and
/// so continuing its history.
///
/// Which history that is comes from the store, which recorded it beside the
/// earlier run; this only says whose.
#[derive(Debug, Clone, PartialEq)]
pub struct Continuation {
    /// Hex group fingerprint after the rule change.
    pub group: String,
    /// Hex group fingerprint of the group it stands in for.
    pub previous_group: String,
    /// Occurrences both groups place identically.
    pub shared: usize,
    /// Shared placements as a fraction of the smaller group.
    pub overlap: f64,
}

/// Which groups of two runs of one tree stand in the same places.
///
/// The two directions are settled independently. A group of the earlier run
/// asks which later group took its place, which is what a baseline entry needs
/// rewriting to; a group of the later run asks which earlier group it stands
/// in for, which is whose history it continues. Where two groups merged into
/// one the answers differ, and each is right about its own question.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Mapping {
    /// One entry per group of the earlier run that a later group stands in for.
    pub carried: Vec<Carried>,
    /// Hex fingerprints of the earlier run's groups nothing stands in for.
    pub stale: Vec<String>,
    /// One entry per group of the later run that continues an earlier history.
    pub continuations: Vec<Continuation>,
}

/// One possible pairing, before the best is chosen.
struct Candidate {
    other: usize,
    shared: usize,
    overlap: f64,
    jaccard: f64,
}

/// Pair the groups of two runs by where their occurrences sit.
///
/// Both sides must come from runs that read the same text. Establishing that
/// is the caller's: this layer cannot tell a rule change from a rewrite.
#[must_use]
pub fn by_place(previous: &[StoredGroup], current: &[StoredGroup]) -> Mapping {
    let before: Vec<BTreeSet<Placement>> = previous.iter().map(placements).collect();
    let after: Vec<BTreeSet<Placement>> = current.iter().map(placements).collect();

    // Which groups of the later run hold a given placement, so pairings are
    // found by what they share rather than by comparing every pair.
    let mut holders: BTreeMap<&Placement, Vec<usize>> = BTreeMap::new();
    for (index, places) in after.iter().enumerate() {
        for place in places {
            holders.entry(place).or_default().push(index);
        }
    }

    let mut carried = Vec::new();
    let mut stale = Vec::new();
    for (index, places) in before.iter().enumerate() {
        let best = best_match(places, &after, &holders, |other| {
            current[other].fingerprint_hex.as_str()
        });
        match best {
            Some(candidate) => carried.push(Carried {
                from: previous[index].fingerprint_hex.clone(),
                to: current[candidate.other].fingerprint_hex.clone(),
                findings: current[candidate.other]
                    .members
                    .iter()
                    .map(|member| member.finding_hex.clone())
                    .collect(),
                shared: candidate.shared,
                overlap: candidate.overlap,
            }),
            None => stale.push(previous[index].fingerprint_hex.clone()),
        }
    }

    let mut back: BTreeMap<&Placement, Vec<usize>> = BTreeMap::new();
    for (index, places) in before.iter().enumerate() {
        for place in places {
            back.entry(place).or_default().push(index);
        }
    }
    let continuations = after
        .iter()
        .enumerate()
        .filter_map(|(index, places)| {
            let candidate = best_match(places, &before, &back, |other| {
                previous[other].fingerprint_hex.as_str()
            })?;
            Some(Continuation {
                group: current[index].fingerprint_hex.clone(),
                previous_group: previous[candidate.other].fingerprint_hex.clone(),
                shared: candidate.shared,
                overlap: candidate.overlap,
            })
        })
        .collect();

    Mapping {
        carried,
        stale,
        continuations,
    }
}

/// The group on the other side that best stands in for one set of placements,
/// or `None` when none shares enough of them.
///
/// Ties fall to the wider agreement, then to fingerprint order, so the pairing
/// never depends on the order the groups were read in.
fn best_match<'a>(
    places: &BTreeSet<Placement>,
    others: &[BTreeSet<Placement>],
    holders: &BTreeMap<&Placement, Vec<usize>>,
    fingerprint: impl Fn(usize) -> &'a str,
) -> Option<Candidate> {
    let mut shared_counts: BTreeMap<usize, usize> = BTreeMap::new();
    for place in places {
        for index in holders.get(place).into_iter().flatten() {
            *shared_counts.entry(*index).or_default() += 1;
        }
    }
    let mut candidates: Vec<Candidate> = shared_counts
        .into_iter()
        .filter_map(|(other, shared)| {
            let theirs = &others[other];
            let smaller = theirs.len().min(places.len());
            let union = theirs.len() + places.len() - shared;
            let overlap = ratio(shared, smaller);
            (overlap >= LINEAGE_MIN_OVERLAP).then(|| Candidate {
                other,
                shared,
                overlap,
                jaccard: ratio(shared, union),
            })
        })
        .collect();
    candidates.sort_by(|a, b| {
        b.overlap
            .total_cmp(&a.overlap)
            .then_with(|| b.jaccard.total_cmp(&a.jaccard))
            .then_with(|| fingerprint(a.other).cmp(fingerprint(b.other)))
    });
    candidates.into_iter().next()
}

/// Where a stored group's occurrences sit, deduplicated: two occurrences at
/// one address are one place, and the fraction below counts places.
fn placements(group: &StoredGroup) -> BTreeSet<Placement> {
    group.members.iter().map(Placement::of).collect()
}

/// `numerator / denominator`, answering zero for an empty denominator rather
/// than a non-number that would poison every later comparison.
fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)] // group sizes are far below 2^53
    {
        numerator as f64 / denominator as f64
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn member(file: &str, unit: &str, start: i64, finding: &str) -> StoredMember {
        StoredMember {
            finding_hex: finding.to_string(),
            content_hex: "c0".repeat(16),
            language: "rust".to_string(),
            file_path: file.to_string(),
            start_line: Some(start),
            end_line: Some(start + 9),
            token_count: 42,
            unit_name: Some(unit.to_string()),
            is_canonical: false,
        }
    }

    fn group(fingerprint: &str, members: Vec<StoredMember>) -> StoredGroup {
        StoredGroup {
            fingerprint_hex: fingerprint.to_string(),
            clone_type: "type-2".to_string(),
            member_scope: "unit".to_string(),
            score: 0.9,
            entropy_bits: 4.0,
            suppress_reason: None,
            boilerplate: None,
            split_pair: false,
            test_code: false,
            similarity: None,
            suppressed_by: None,
            members,
        }
    }

    /// One duplication in two files, named differently by each run.
    fn one_group(fingerprint: &str, findings: [&str; 2]) -> StoredGroup {
        group(
            fingerprint,
            vec![
                member("src/a.rs", "parse", 10, findings[0]),
                member("src/b.rs", "parse", 30, findings[1]),
            ],
        )
    }

    #[test]
    fn a_group_that_moved_only_its_name_is_carried_across() {
        let before = vec![one_group("aa", ["f1", "f2"])];
        let after = vec![one_group("bb", ["g1", "g2"])];

        let mapping = by_place(&before, &after);
        assert_eq!(mapping.carried.len(), 1);
        assert_eq!(mapping.carried[0].from, "aa");
        assert_eq!(mapping.carried[0].to, "bb");
        assert_eq!(mapping.carried[0].findings, vec!["g1", "g2"]);
        assert!((mapping.carried[0].overlap - 1.0).abs() < f64::EPSILON);
        assert!(mapping.stale.is_empty());
        assert_eq!(mapping.continuations.len(), 1);
        assert_eq!(mapping.continuations[0].group, "bb");
        assert_eq!(mapping.continuations[0].previous_group, "aa");
    }

    #[test]
    fn a_duplication_the_new_rules_no_longer_find_is_reported_stale() {
        let before = vec![one_group("aa", ["f1", "f2"])];
        let mapping = by_place(&before, &[]);

        assert!(mapping.carried.is_empty());
        assert_eq!(mapping.stale, vec!["aa".to_string()]);
        assert!(mapping.continuations.is_empty());
    }

    #[test]
    fn a_finding_at_a_place_nothing_stood_before_is_not_paired_with_a_neighbour() {
        // The same unit, a stretch starting three lines further down. Nothing
        // judged that region, and re-pointing a suppression at it would hide
        // code nobody looked at.
        let before = vec![one_group("aa", ["f1", "f2"])];
        let after = vec![group(
            "bb",
            vec![
                member("src/a.rs", "parse", 13, "g1"),
                member("src/b.rs", "parse", 33, "g2"),
            ],
        )];

        let mapping = by_place(&before, &after);
        assert!(mapping.carried.is_empty());
        assert_eq!(mapping.stale, vec!["aa".to_string()]);
    }

    #[test]
    fn half_of_the_smaller_group_is_the_thinnest_pairing_accepted() {
        // One of two placements survives: the same floor the ordinary
        // comparison draws, and for the same reason.
        let before = vec![one_group("aa", ["f1", "f2"])];
        let after = vec![group(
            "bb",
            vec![
                member("src/a.rs", "parse", 10, "g1"),
                member("src/c.rs", "parse", 50, "g2"),
            ],
        )];

        let mapping = by_place(&before, &after);
        assert_eq!(mapping.carried.len(), 1);
        assert_eq!(mapping.carried[0].shared, 1);
        assert!((mapping.carried[0].overlap - LINEAGE_MIN_OVERLAP).abs() < f64::EPSILON);
    }

    #[test]
    fn one_placement_out_of_four_is_too_thin_to_pair() {
        let before = vec![group(
            "aa",
            vec![
                member("src/a.rs", "one", 10, "f1"),
                member("src/b.rs", "two", 20, "f2"),
                member("src/c.rs", "three", 30, "f3"),
                member("src/d.rs", "four", 40, "f4"),
            ],
        )];
        let after = vec![group(
            "bb",
            vec![
                member("src/a.rs", "one", 10, "g1"),
                member("src/x.rs", "x", 50, "g2"),
                member("src/y.rs", "y", 60, "g3"),
                member("src/z.rs", "z", 70, "g4"),
            ],
        )];

        let mapping = by_place(&before, &after);
        assert!(mapping.carried.is_empty());
        assert_eq!(mapping.stale, vec!["aa".to_string()]);
    }

    #[test]
    fn two_groups_standing_where_one_did_each_answer_their_own_question() {
        // The rules split one group in two. Both pieces continue the history
        // they came from, while the baseline entry can only be rewritten to
        // one id — the piece that holds most of what it froze.
        let before = vec![group(
            "aa",
            vec![
                member("src/a.rs", "one", 10, "f1"),
                member("src/b.rs", "two", 20, "f2"),
                member("src/c.rs", "three", 30, "f3"),
                member("src/d.rs", "four", 40, "f4"),
            ],
        )];
        let after = vec![
            group(
                "bb",
                vec![
                    member("src/a.rs", "one", 10, "g1"),
                    member("src/b.rs", "two", 20, "g2"),
                ],
            ),
            group(
                "cc",
                vec![
                    member("src/c.rs", "three", 30, "g3"),
                    member("src/d.rs", "four", 40, "g4"),
                ],
            ),
        ];

        let mapping = by_place(&before, &after);
        assert_eq!(mapping.carried.len(), 1);
        assert_eq!(
            mapping.carried[0].to, "bb",
            "ties fall to fingerprint order"
        );
        assert_eq!(
            mapping.continuations.len(),
            2,
            "both pieces keep the history"
        );
        assert!(
            mapping
                .continuations
                .iter()
                .all(|carried| carried.previous_group == "aa")
        );
    }

    #[test]
    fn the_pairing_does_not_depend_on_the_order_the_groups_were_read_in() {
        let before = vec![one_group("aa", ["f1", "f2"])];
        let after = vec![
            one_group("bb", ["g1", "g2"]),
            group(
                "cc",
                vec![
                    member("src/a.rs", "parse", 10, "h1"),
                    member("src/b.rs", "parse", 30, "h2"),
                ],
            ),
        ];

        let forward = by_place(&before, &after);
        let reversed = by_place(&before, &[after[1].clone(), after[0].clone()]);
        assert_eq!(forward.carried, reversed.carried);
        assert_eq!(forward.stale, reversed.stale);
    }

    #[test]
    fn a_run_that_found_nothing_before_leaves_every_new_group_on_its_own() {
        let after = vec![one_group("bb", ["g1", "g2"])];
        let mapping = by_place(&[], &after);

        assert!(mapping.carried.is_empty());
        assert!(mapping.stale.is_empty());
        assert!(mapping.continuations.is_empty());
    }
}
