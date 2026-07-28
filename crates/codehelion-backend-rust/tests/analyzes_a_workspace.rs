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

use codehelion_helper::ir::{TypeCategory, Unavailability, UnitRef};
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

/// The handshake is where a helper says what it is. Claiming a capability it
/// does not have would be worse than claiming none: a run stops recording that
/// it did not get something once it has been told it would.
#[test]
fn the_helper_says_which_compiler_will_answer_and_what_it_can_supply() {
    let helper = helper();
    assert!(helper.offers(Capability::Types));
    assert!(!helper.offers(Capability::MirCfg));
    helper.shutdown().unwrap();
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
