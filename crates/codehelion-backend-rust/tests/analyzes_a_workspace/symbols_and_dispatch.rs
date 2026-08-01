use super::*;

#[test]
fn the_helper_says_which_compiler_will_answer_and_what_it_can_supply() {
    let helper = helper();
    assert!(helper.offers(Capability::Types));
    assert!(helper.offers(Capability::NameResolution));
    assert!(helper.offers(Capability::CallTargets));
    assert!(helper.offers(Capability::MacroExpansion));
    assert!(helper.offers(Capability::TemplateInstantiation));
    assert!(!helper.offers(Capability::MirCfg));
    helper.shutdown().unwrap();
}

/// What normalization is for. A name defined outside the scan is an interface
/// two fragments genuinely share and is compared on; a name defined inside it
/// is a detail one of them happens to have chosen, and is not.
#[test]
fn a_name_the_project_did_not_write_is_marked_as_coming_from_outside() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    for outside in ["String", "Vec", "i64"] {
        let found = names(&ir, outside);
        assert!(!found.is_empty(), "{outside} was never resolved");
        for symbol in found {
            assert!(symbol.external, "{outside} was called part of the scan");
        }
    }
    for inside in ["Entry", "debits", "total", "entries"] {
        let found = names(&ir, inside);
        assert!(!found.is_empty(), "{inside} was never resolved");
        for symbol in found {
            assert!(!symbol.external, "{inside} was called a library name");
        }
    }
}

/// The offsets are the whole mechanism: normalization looks a name up by the
/// byte it starts at, so an anchor pointing anywhere near the name rather than
/// at it resolves a different name, or none, without saying so.
#[test]
fn a_name_is_anchored_on_the_name_rather_than_near_it() {
    let source = codehelion_fixtures::rust("plain")
        .unwrap()
        .join("ledger/src/lib.rs");
    let text = std::fs::read_to_string(source).expect("the fixture is readable");
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    // Bindings only, because a declaration's anchor spans the whole item it
    // declares. A binding is only ever reported as an occurrence.
    let bindings: Vec<_> = ir
        .symbols
        .iter()
        .filter(|symbol| symbol.kind == SymbolKind::Binding)
        .collect();
    assert!(!bindings.is_empty(), "no binding was resolved at all");
    for symbol in bindings {
        let range = &symbol.anchor.expansion;
        let start = usize::try_from(range.start_byte).unwrap();
        let end = usize::try_from(range.end_byte).unwrap();
        assert_eq!(&text[start..end], symbol.name);
    }
}

/// `total` is written in both `debits` and `credits`, and they are two
/// bindings. An identity two definitions share is not an identity, and here it
/// would make the two functions look like they touch one variable.
#[test]
fn two_bindings_that_share_a_name_do_not_share_an_identity() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    let totals = names(&ir, "total");
    assert!(totals.len() >= 4, "expected several mentions of total");
    let identities: std::collections::BTreeSet<&str> =
        totals.iter().map(|symbol| symbol.id.as_str()).collect();
    assert_eq!(identities.len(), 2, "{identities:?}");
}

/// A local's type is the one nothing else records and the one a structural
/// reading cannot see: `total` is only ever written as `0`.
#[test]
fn a_binding_carries_the_type_the_compiler_inferred_for_it() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert_eq!(category_of(&ir, "total"), TypeCategory::Integer);
}

/// The dispatch fixture is one crate whose file is its own root.
fn dispatch() -> Box<CompilerIr> {
    let file = codehelion_fixtures::rust("dispatch")
        .unwrap()
        .join("src/lib.rs");
    analyzed(&UnitRef {
        unit: "dispatch".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    })
}

/// What a call written inside `enclosing` was found to reach.
fn targets(ir: &CompilerIr, source: &str, enclosing: &str) -> Vec<CallTarget> {
    let body = body_of(source, enclosing);
    ir.calls
        .iter()
        .filter(|call| {
            let range = &call.anchor.expansion;
            body.contains(&usize::try_from(range.start_byte).unwrap())
        })
        .map(|call| call.target.clone())
        .collect()
}

fn fixture_source() -> String {
    source_of("dispatch")
}

/// A concrete receiver settles which body runs, and it settles it even when
/// the body was written on the trait: nothing overrides `doubled`, so the
/// trait's own body is the one that runs. Calling that dynamic would say the
/// compiler knew less than it did.
#[test]
fn a_concrete_receiver_reaches_one_body_wherever_that_body_was_written() {
    let ir = dispatch();
    let found = targets(&ir, &fixture_source(), "pub fn concrete");
    assert_eq!(found.len(), 2, "{found:?}");
    for target in &found {
        assert!(
            matches!(target, CallTarget::Static { .. }),
            "a concrete receiver was reported as undecided: {target:?}"
        );
    }
    let symbols: Vec<&str> = found
        .iter()
        .filter_map(|target| match target {
            CallTarget::Static { symbol } => Some(symbol.as_str()),
            _ => None,
        })
        .collect();
    assert!(
        symbols.iter().any(|symbol| symbol.contains("Segment")),
        "{symbols:?}"
    );
    assert!(
        symbols.iter().any(|symbol| symbol.contains("doubled")),
        "{symbols:?}"
    );
}

/// A type parameter does not settle it. Which body runs is decided where the
/// function is instantiated, and the honest answer is the set the scan can
/// see — here, the two implementations written beside it.
#[test]
fn a_type_parameter_receiver_is_one_of_the_implementations_in_the_scan() {
    let ir = dispatch();
    let found = targets(&ir, &fixture_source(), "pub fn generic");
    assert_eq!(found.len(), 1, "{found:?}");
    match &found[0] {
        CallTarget::Dynamic { candidates } => {
            assert_eq!(candidates.len(), 2, "{candidates:?}");
            assert!(candidates.iter().any(|c| c.contains("Segment")));
            assert!(candidates.iter().any(|c| c.contains("Tally")));
        }
        other => panic!("a generic receiver was reported as settled: {other:?}"),
    }
}

/// And a trait object does not settle it either, for a different reason: the
/// choice is made while the program runs rather than while it is compiled.
/// The evidence is the same set, which is the point of keeping the set.
#[test]
fn a_trait_object_receiver_is_the_same_set_as_a_type_parameter() {
    let ir = dispatch();
    let source = fixture_source();
    let erased = targets(&ir, &source, "pub fn erased");
    let generic = targets(&ir, &source, "pub fn generic");
    assert_eq!(erased, generic, "{erased:?} against {generic:?}");
}

/// Calling a value has no definition to point at, and saying so is the
/// answer. A call reported as reaching something it does not would be worse
/// than one reported as unknown.
#[test]
fn calling_a_value_rather_than_a_name_reaches_nothing_nameable() {
    let ir = dispatch();
    let found = targets(&ir, &fixture_source(), "pub fn indirect");
    assert_eq!(found, vec![CallTarget::Unresolved], "{found:?}");
}
