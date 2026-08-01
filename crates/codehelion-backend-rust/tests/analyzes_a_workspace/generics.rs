use super::*;

/// The whole point of recording an instantiation: two calls that produce two
/// copies of a body have to say which one body they came from, or they read as
/// two bodies that happen to agree.
#[test]
fn two_uses_of_one_generic_name_the_body_they_share() {
    let ir = stamped();
    let found = stamps(&ir, "stamped::widest");
    assert_eq!(found.len(), 2, "{:?}", ir.instantiations);
    let source = source_of("generic");
    let written = found[0]
        .anchor
        .definition
        .as_ref()
        .expect("an instantiation names where its body was written");
    assert_eq!(
        found[1].anchor.definition.as_ref(),
        Some(written),
        "the two stamps disagree about where the one body is"
    );
    let start = usize::try_from(written.start_byte).unwrap();
    let end = usize::try_from(written.end_byte).unwrap();
    assert!(
        source[start..end].contains("pub fn widest<T: Ord + Copy>"),
        "the definition range is not the generic: {:?}",
        &source[start..end]
    );
    // And each is anchored on the use, which is the only place in this file
    // either of them can be pointed at.
    for stamp in found {
        let at = usize::try_from(stamp.anchor.expansion.start_byte).unwrap();
        let to = usize::try_from(stamp.anchor.expansion.end_byte).unwrap();
        assert_eq!(&source[at..to], "widest");
    }
}

/// The other half of the same answer. One definition is what there is to fix;
/// the number of families is how many copies of it a build carries, and those
/// are different questions with different answers.
#[test]
fn substituting_a_different_type_is_a_different_family() {
    let ir = stamped();
    let mut keys: Vec<&str> = stamps(&ir, "stamped::widest")
        .iter()
        .map(|stamp| stamp.instantiation_key.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["stamped::widest<i64>", "stamped::widest<u32>"]);
}

/// A type is stamped out the same way a function is, and it is stamped out
/// wherever it is named — in a signature as much as in a body. A reading that
/// only looked inside bodies would report nothing at all about a project that
/// passes its generic types through signatures.
#[test]
fn a_generic_type_is_stamped_out_wherever_it_is_named() {
    let ir = stamped();
    let found = stamps(&ir, "stamped::Pair");
    assert_eq!(found.len(), 2, "{:?}", ir.instantiations);
    assert!(
        found
            .iter()
            .all(|stamp| stamp.instantiation_key == "stamped::Pair<i64>"),
        "one type at one argument is one family: {found:?}"
    );
    let source = source_of("generic");
    let signature = source.find("-> Pair<i64>").expect("the signature") + "-> ".len();
    let literal = source.find("Pair { left").expect("the literal");
    let places: Vec<usize> = found
        .iter()
        .map(|stamp| usize::try_from(stamp.anchor.expansion.start_byte).unwrap())
        .collect();
    assert_eq!(
        places,
        [signature, literal],
        "the two stamps are not the signature and the literal"
    );
}

/// The substituted types are recorded as the shapes the unit compares on
/// rather than as their spellings, which is why the key carries the spelling.
#[test]
fn what_was_substituted_is_recorded_as_a_shape() {
    let ir = stamped();
    let stamp = stamps(&ir, "stamped::widest")
        .into_iter()
        .find(|stamp| stamp.instantiation_key == "stamped::widest<i64>")
        .expect("the i64 stamp");
    assert_eq!(stamp.arguments.len(), 1);
    let argument = usize::try_from(stamp.arguments[0]).unwrap();
    assert_eq!(ir.types[argument].category, TypeCategory::Integer);
}

/// Reading `values.first()` instantiates a standard-library generic, and so
/// does nearly every line of nearly every crate. None of it is repetition
/// anybody scanning this project can act on, and counting it would make the
/// family index a reading of the dependency tree.
#[test]
fn a_body_the_project_did_not_write_is_not_counted_as_repetition() {
    let ir = stamped();
    assert!(!ir.instantiations.is_empty());
    for stamp in &ir.instantiations {
        assert!(
            stamp.definition.starts_with("stamped::"),
            "{} came from outside the scan",
            stamp.definition
        );
    }
}

/// The control. Nothing about a function that is not generic gets stamped out,
/// so an analysis that reports one here is reporting one for every call in
/// every crate.
#[test]
fn a_body_that_is_not_generic_stamps_out_nothing() {
    let ir = stamped();
    let body = body_of(&source_of("generic"), "pub fn total");
    let inside: Vec<&Instantiation> = ir
        .instantiations
        .iter()
        .filter(|stamp| body.contains(&usize::try_from(stamp.anchor.expansion.start_byte).unwrap()))
        .collect();
    assert!(inside.is_empty(), "{inside:?}");
}
