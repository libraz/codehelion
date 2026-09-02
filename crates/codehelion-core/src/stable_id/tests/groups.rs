//! Clone group fingerprints and the lineage identifier taken from them.

use super::*;

#[test]
fn a_lineage_has_its_own_stable_identifier_domain() {
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
    assert_eq!(group_lineage_id(&group), group_lineage_id(&group));
    assert_ne!(group_lineage_id(&group).as_bytes(), group.as_bytes());
}
#[test]
fn group_fingerprint_is_order_independent_and_deduplicated() {
    let a = fragment_fingerprint(&variant(), &ctx(), "member", &sample(), ContentNorm::Raw);
    let b = fragment_fingerprint(
        &variant(),
        &ctx(),
        "member",
        &renamed_sample(),
        ContentNorm::Raw,
    );
    let forward = clone_group_fingerprint(&variant(), CloneClass::Type1, &[a, b]);
    let reversed = clone_group_fingerprint(&variant(), CloneClass::Type1, &[b, a]);
    assert_eq!(forward, reversed);
    // Another copy of known content leaves the fingerprint unchanged.
    let duplicated = clone_group_fingerprint(&variant(), CloneClass::Type1, &[a, b, a]);
    assert_eq!(forward, duplicated);
    // New member content changes it.
    let single = clone_group_fingerprint(&variant(), CloneClass::Type1, &[a]);
    assert_ne!(forward, single);
}

#[test]
fn structural_group_fingerprint_is_anchored_and_order_independent() {
    let a = fragment_fingerprint(&variant(), &ctx(), "member", &sample(), ContentNorm::Raw);
    let b = fragment_fingerprint(
        &variant(),
        &ctx(),
        "member",
        &renamed_sample(),
        ContentNorm::Raw,
    );
    let members = [a, b];
    let forward = structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &a, &members);
    // Member order does not matter.
    let reversed = structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &a, &[b, a]);
    assert_eq!(forward, reversed);
    // A different canonical instance (medoid) over the same set hashes apart.
    let other_anchor =
        structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &b, &members);
    assert_ne!(forward, other_anchor);
    // New member content changes it.
    let c = fragment_fingerprint(
        &variant(),
        &ctx(),
        "member",
        &toks(&[(Kw, "let"), (Id, "z"), (Pu, ";")]),
        ContentNorm::Raw,
    );
    let grown = structural_clone_group_fingerprint(&variant(), CloneClass::Type3, &a, &[a, b, c]);
    assert_ne!(forward, grown);
}
