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

use codehelion_helper::ir::{ResolvedSymbol, SymbolKind, TypeCategory, Unavailability, UnitRef};
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
