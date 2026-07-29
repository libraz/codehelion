//! What this helper reports about projects whose answer is known by reading
//! them.
//!
//! Driven through the real client against the real program, because everything
//! worth checking here is a claim about two processes: that the handshake
//! agrees, that a unit comes back with types a person can verify by looking at
//! the fixture, that a crate needing a build script is declined rather than
//! half-answered, and that declining it leaves no trace of having run it.
//!
//! `CARGO_BIN_EXE_` rather than a constructed path: a test that guesses where a
//! binary lands can run a stale copy and report success.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::time::Duration;

use codehelion_helper::ir::{
    CallTarget, ResolvedSymbol, SymbolKind, TypeCategory, Unavailability, UnitRef,
};
use codehelion_helper::protocol::Capability;
use codehelion_helper::{Analysis, COMPILER_IR_SCHEMA_VERSION, CompilerIr, Helper};

/// Loading a workspace reads its sysroot and its metadata, which on a cold
/// machine is slower than the protocol's default.
const PATIENT: Duration = Duration::from_mins(5);

fn helper() -> Helper {
    Helper::start(
        std::path::Path::new(env!("CARGO_BIN_EXE_codehelion-backend-rust")),
        PATIENT,
    )
    .expect("the helper should start and shake hands")
}

fn unit(fixture: &str, member: &str, crate_name: &str) -> UnitRef {
    let file = codehelion_fixtures::rust(fixture)
        .unwrap()
        .join(member)
        .join("src/lib.rs");
    UnitRef {
        unit: crate_name.to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    }
}

fn analyze(unit: &UnitRef) -> Analysis {
    let mut helper = helper();
    let analysis = helper
        .analyze(unit, &[Capability::Types])
        .expect("the helper should answer");
    helper.shutdown().expect("the helper should stop cleanly");
    analysis
}

fn analyzed(unit: &UnitRef) -> Box<CompilerIr> {
    match analyze(unit) {
        Analysis::Done(ir) => ir,
        Analysis::Missing(reason) => panic!("expected an analysis, got {reason:?}"),
    }
}

fn category_of(ir: &CompilerIr, name: &str) -> TypeCategory {
    let symbol = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == name)
        .unwrap_or_else(|| {
            panic!(
                "no symbol called {name}; the unit holds {:?}",
                ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
            )
        });
    let index = symbol
        .type_index
        .unwrap_or_else(|| panic!("{name} has no resolved type")) as usize;
    ir.types[index].category
}

/// Every name written in `file`, in the order they were written.
fn names<'a>(ir: &'a CompilerIr, name: &str) -> Vec<&'a ResolvedSymbol> {
    ir.symbols
        .iter()
        .filter(|symbol| symbol.name == name)
        .collect()
}

/// The handshake is where a helper says what it is. Claiming a capability it
/// does not have would be worse than claiming none: a run stops recording that
/// it did not get something once it has been told it would.
#[test]
fn the_helper_says_which_compiler_will_answer_and_what_it_can_supply() {
    let helper = helper();
    assert!(helper.offers(Capability::Types));
    assert!(helper.offers(Capability::NameResolution));
    assert!(helper.offers(Capability::CallTargets));
    assert!(helper.offers(Capability::MacroExpansion));
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

/// The byte range of one function's body, found by reading the fixture the
/// same way a person would.
fn body_of(source: &str, enclosing: &str) -> std::ops::Range<usize> {
    let start = source
        .find(enclosing)
        .unwrap_or_else(|| panic!("the fixture no longer contains {enclosing}"));
    let open = start + source[start..].find('{').expect("a body");
    let mut depth = 0_i32;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return open..open + offset;
                }
            }
            _ => {}
        }
    }
    panic!("{enclosing} has no closing brace");
}

fn fixture_source() -> String {
    let path = codehelion_fixtures::rust("dispatch")
        .unwrap()
        .join("src/lib.rs");
    std::fs::read_to_string(path).expect("the fixture is readable")
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

/// The macro fixture is one crate whose file is its own root.
fn repeated() -> Box<CompilerIr> {
    let file = codehelion_fixtures::rust("macro-rules")
        .unwrap()
        .join("src/lib.rs");
    analyzed(&UnitRef {
        unit: "repeated".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    })
}

/// A declarative macro is expanded by reading it, so what it declared is
/// there to be reported. Leaving it out would report a file as holding less
/// than it does.
#[test]
fn what_a_declarative_macro_declared_is_reported() {
    let ir = repeated();
    for produced in ["Reads", "Writes"] {
        // Exactly one: the declaration walk passes over what it cannot place,
        // and this pass places it. Both reporting it would put two of one type
        // in a unit that holds one.
        let found = names(&ir, produced)
            .into_iter()
            .filter(|symbol| symbol.kind == SymbolKind::Type)
            .count();
        assert_eq!(
            found,
            1,
            "{produced}: {:?}",
            ir.symbols.iter().map(|s| &s.name).collect::<Vec<_>>()
        );
    }
}

/// The claim the whole two-part anchor exists for. Both types came out of one
/// macro, so they share a definition site and differ only in where they were
/// invoked — which is what lets a group say "written once, expanded twice"
/// instead of reporting a duplication nobody can remove.
#[test]
fn two_expansions_of_one_macro_share_the_place_it_was_written() {
    let ir = repeated();
    let reads = expanded_type(&ir, "Reads");
    let writes = expanded_type(&ir, "Writes");
    assert_eq!(
        reads.anchor.definition, writes.anchor.definition,
        "two expansions of one macro were attributed to two definitions"
    );
    assert_ne!(
        reads.anchor.expansion, writes.anchor.expansion,
        "two invocations were reported at one place"
    );
}

/// And what somebody typed carries no second place, or the distinction the
/// definition site draws would be no distinction at all.
#[test]
fn what_was_typed_out_is_not_attributed_to_a_macro() {
    let ir = repeated();
    let manual = ir
        .symbols
        .iter()
        .find(|symbol| symbol.name == "Manual")
        .expect("the hand-written type");
    assert_eq!(manual.anchor.definition, None);
}

/// An expansion anchors at the invocation, because that is the only place in
/// the file it can be pointed at: the text of the produced item is not there.
#[test]
fn an_expansion_anchors_on_the_invocation_that_produced_it() {
    let path = codehelion_fixtures::rust("macro-rules")
        .unwrap()
        .join("src/lib.rs");
    let text = std::fs::read_to_string(path).expect("the fixture is readable");
    let ir = repeated();
    let reads = expanded_type(&ir, "Reads");
    let range = &reads.anchor.expansion;
    let start = usize::try_from(range.start_byte).unwrap();
    let end = usize::try_from(range.end_byte).unwrap();
    assert_eq!(&text[start..end], "counter!(Reads);");
    // And the definition site is the macro, which is somewhere else entirely.
    // It spans the item as written, doc comment included, the same way every
    // other declaration's anchor does.
    let written = reads.anchor.definition.as_ref().expect("a definition site");
    let start = usize::try_from(written.start_byte).unwrap();
    let end = usize::try_from(written.end_byte).unwrap();
    let source = &text[start..end];
    assert!(source.contains("macro_rules! counter"), "{source:?}");
    assert!(end <= usize::try_from(range.start_byte).unwrap());
}

fn expanded_type<'a>(ir: &'a CompilerIr, name: &str) -> &'a ResolvedSymbol {
    ir.symbols
        .iter()
        .find(|symbol| symbol.name == name && symbol.kind == SymbolKind::Type)
        .unwrap_or_else(|| panic!("no type called {name}"))
}

/// The baseline. Every category asserted here can be checked by opening the
/// fixture: `amount` is an `i64`, `label` is a `String`, and `labels` returns a
/// `Vec<String>`.
#[test]
fn a_plain_workspace_comes_back_with_types_a_reader_can_check() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert_eq!(ir.schema_version, COMPILER_IR_SCHEMA_VERSION);
    assert_eq!(category_of(&ir, "amount"), TypeCategory::Integer);
    // A struct in the standard library, reported by its shape rather than as
    // the record it technically is: the category exists so that this and a C++
    // `std::string` are the same answer.
    assert_eq!(category_of(&ir, "label"), TypeCategory::Text);
    assert_eq!(category_of(&ir, "labels"), TypeCategory::Sequence);
    assert_eq!(category_of(&ir, "debits"), TypeCategory::Integer);
}

/// Anchors have to point at the fixture's own text, since a fragment is cut
/// from a file and a finding anchored anywhere else is unusable.
#[test]
fn every_symbol_is_anchored_where_it_was_written() {
    let ir = analyzed(&unit("plain", "ledger", "ledger"));
    assert!(!ir.symbols.is_empty());
    for symbol in &ir.symbols {
        let anchor = &symbol.anchor.expansion;
        assert_eq!(anchor.file, "ledger/src/lib.rs", "{}", symbol.name);
        assert!(anchor.end_byte > anchor.start_byte, "{}", symbol.name);
        assert!(anchor.start_line >= 1, "{}", symbol.name);
        // Written where it stands: nothing here comes from a macro, and
        // claiming otherwise would put a definition nobody wrote at a place
        // somebody did.
        assert_eq!(symbol.anchor.definition, None, "{}", symbol.name);
    }
}

/// A crate whose types only exist after a build script has run cannot be
/// analysed without running it. Answering with whatever happens to resolve
/// would report a partial reading as a complete one.
#[test]
fn a_crate_that_needs_its_build_script_is_declined_by_name() {
    let file = codehelion_fixtures::rust("build-script")
        .unwrap()
        .join("src/lib.rs");
    let unit = UnitRef {
        unit: "generated-tables".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    };
    match analyze(&unit) {
        Analysis::Missing(reason) => assert_eq!(reason, Unavailability::RequiresExecution),
        Analysis::Done(ir) => panic!("analysed a crate it could not have read: {ir:?}"),
    }
}

/// And declining it has to leave no trace of having run it. The two are not the
/// same claim: a helper that ran the build script and then reported
/// `RequiresExecution` would pass the test above.
#[test]
fn declining_a_build_script_does_not_run_it() {
    let marker = codehelion_fixtures::execution_marker("build-script").unwrap();
    assert!(
        !marker.exists(),
        "{} existed before the helper was asked anything",
        marker.display()
    );
    let file = codehelion_fixtures::rust("build-script")
        .unwrap()
        .join("src/lib.rs");
    let _ = analyze(&UnitRef {
        unit: "generated-tables".to_string(),
        file: file.display().to_string(),
        variant: "host".to_string(),
    });
    assert!(
        !marker.exists(),
        "{} appeared: the helper ran the fixture's build script",
        marker.display()
    );
}

/// One process, asked twice, must not answer differently the second time. The
/// workspace is cached between requests, and a cache that changed an answer
/// would be a cache that made results depend on what was asked before.
#[test]
fn asking_twice_in_one_process_gives_the_same_answer() {
    let target = unit("plain", "ledger", "ledger");
    let mut helper = helper();
    let first = helper.analyze(&target, &[Capability::Types]).unwrap();
    let second = helper.analyze(&target, &[Capability::Types]).unwrap();
    helper.shutdown().unwrap();
    assert_eq!(first, second);
}

/// A unit nobody can place is refused rather than guessed at.
#[test]
fn a_unit_outside_any_project_is_reported_as_having_no_build_information() {
    let unit = UnitRef {
        unit: "nothing".to_string(),
        file: "/nowhere/at/all/src/lib.rs".to_string(),
        variant: "host".to_string(),
    };
    match analyze(&unit) {
        Analysis::Missing(reason) => assert_eq!(reason, Unavailability::NoBuildInformation),
        Analysis::Done(ir) => panic!("analysed a project that is not there: {ir:?}"),
    }
}
