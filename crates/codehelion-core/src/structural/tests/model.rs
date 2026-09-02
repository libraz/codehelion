//! Resolved type and API evidence attributed to a unit.

use super::*;

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
