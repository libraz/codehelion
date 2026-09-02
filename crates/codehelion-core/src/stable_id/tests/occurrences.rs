//! Occurrence discriminators, ranks and the finding ids built on them.

use super::*;

#[test]
fn finding_ids_discriminate_host_and_rank() {
    let group = clone_group_fingerprint(
        &variant(),
        CloneClass::Type1,
        &[fragment_fingerprint(
            &variant(),
            &ctx(),
            "member",
            &sample(),
            ContentNorm::Raw,
        )],
    );
    let host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    let file = OccurrenceDiscriminator::of_tokens(&sample());
    let first = finding_id(&group, OccurrenceScope::Unit(&host), 0);
    let second = finding_id(&group, OccurrenceScope::Unit(&host), 1);
    let outside_units = finding_id(&group, OccurrenceScope::File(file), 0);
    assert_ne!(first, second);
    assert_ne!(first, outside_units);
    // Deterministic: same inputs, same id.
    assert_eq!(first, finding_id(&group, OccurrenceScope::Unit(&host), 0));
}

/// An occurrence outside every unit is identified inside its own file, so two
/// such occurrences in files of different content never share a rank sequence
/// and never collide.
#[test]
fn occurrences_outside_units_are_identified_inside_their_own_file() {
    let group = clone_group_fingerprint(
        &variant(),
        CloneClass::Type1,
        &[fragment_fingerprint(
            &variant(),
            &ctx(),
            "member",
            &sample(),
            ContentNorm::Raw,
        )],
    );
    let here = OccurrenceDiscriminator::of_tokens(&sample());
    let there = OccurrenceDiscriminator::of_tokens(&renamed_sample());
    assert_ne!(here, there);
    assert_ne!(
        finding_id(&group, OccurrenceScope::File(here), 0),
        finding_id(&group, OccurrenceScope::File(there), 0),
        "two files of different content discriminate their own occurrences"
    );
    // A unit and a file never share a scope even when the bytes behind them do.
    let host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    assert_ne!(
        OccurrenceScope::Unit(&host).discriminator(),
        OccurrenceScope::File(here).discriminator()
    );
}

/// The canonical nomination follows content, so the order the occurrences
/// arrive in — the tree walk, and therefore any file rename — cannot move it.
#[test]
fn the_canonical_occurrence_does_not_follow_the_order_it_is_given_in() {
    let alpha = OccurrenceDiscriminator::of_tokens(&sample());
    let zeta = OccurrenceDiscriminator::of_tokens(&renamed_sample());
    let nominated =
        |order: &[OccurrenceDiscriminator]| canonical_occurrence(order).map(|index| order[index]);

    assert_eq!(nominated(&[alpha, zeta]), nominated(&[zeta, alpha]));
    assert_eq!(nominated(&[alpha, zeta, alpha]), nominated(&[zeta, alpha]));
    assert_eq!(canonical_occurrence(&[]), None);
}

/// Ranks separate occurrences their discriminator cannot, and nothing else.
#[test]
fn occurrence_ranks_restart_inside_every_discriminator() {
    let first = OccurrenceDiscriminator::of_tokens(&sample());
    let second = OccurrenceDiscriminator::of_tokens(&renamed_sample());
    assert_eq!(
        occurrence_ranks(&[first, second, first, second, first]),
        vec![0, 0, 1, 1, 2]
    );
    assert!(occurrence_ranks(&[]).is_empty());
}

/// Adding a copy of known content elsewhere leaves the identifiers of the
/// occurrences already reported exactly where they were, whether they sit
/// inside a unit or outside every unit.
#[test]
fn a_further_copy_elsewhere_moves_no_existing_identifier() {
    let group = clone_group_fingerprint(
        &variant(),
        CloneClass::Type1,
        &[fragment_fingerprint(
            &variant(),
            &ctx(),
            "member",
            &sample(),
            ContentNorm::Raw,
        )],
    );
    let host = unit_fingerprint(&variant(), &ctx(), &sample(), ContentNorm::Raw);
    let here = OccurrenceDiscriminator::of_tokens(&sample());
    let there = OccurrenceDiscriminator::of_tokens(&renamed_sample());

    let before = [OccurrenceScope::Unit(&host), OccurrenceScope::File(here)];
    // The new copy sorts ahead of both, as a new file walked first would.
    let after = [
        OccurrenceScope::File(there),
        OccurrenceScope::Unit(&host),
        OccurrenceScope::File(here),
    ];
    let ids = |scopes: &[OccurrenceScope<'_>]| -> Vec<FindingId> {
        let discriminators: Vec<_> = scopes.iter().map(OccurrenceScope::discriminator).collect();
        scopes
            .iter()
            .zip(occurrence_ranks(&discriminators))
            .map(|(scope, rank)| finding_id(&group, *scope, rank))
            .collect()
    };

    assert_eq!(ids(&before), ids(&after)[1..]);
}
