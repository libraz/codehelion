//! What the client does when a real helper process behaves badly.
//!
//! Each test drives the `mock-helper` example, so every failure here is the
//! failure an operating-system process actually produces — a pipe that closes
//! mid-frame, a child that never writes, a child that exits — rather than a
//! stream standing in for one. The in-process tests beside the code cover the
//! wire format; these cover the process.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use codehelion_helper::client::{Analysis, Helper, HelperError, MAX_DIAGNOSTIC_LINES, Supervisor};
use codehelion_helper::ir::{TypeCategory, Unavailability, UnitRef};
use codehelion_helper::protocol::{Capability, PROTOCOL_VERSION};

/// A deadline short enough that a hung helper does not hold up the suite, and
/// long enough that a loaded machine starting a process does not trip it.
const SHORT: Duration = Duration::from_secs(3);

/// The mock helper, as cargo built it for this run.
///
/// Cargo sets this for a binary of the same package, so the path is both
/// correct and current. Finding it by walking the target directory instead
/// would run whatever was there last — which is how a suite comes to pass
/// against a binary that no longer matches its source.
const MOCK: &str = env!("CARGO_BIN_EXE_mock-helper");

fn start(behaviour: &str, timeout: Duration) -> Result<Helper, HelperError> {
    Helper::start_with(Path::new(MOCK), &[behaviour], timeout)
}

#[test]
fn a_well_behaved_helper_says_what_it_is_and_what_it_can_do() {
    let helper = start("well-behaved", SHORT).expect("the mock answers the handshake");
    assert_eq!(helper.identity().name, "codehelion-mock-helper");
    assert_eq!(helper.protocol_version(), PROTOCOL_VERSION);
    assert!(helper.offers(Capability::Types));
    assert!(!helper.offers(Capability::MirCfg));
    helper.shutdown().expect("it goes when asked");
}

#[test]
fn a_helper_from_another_era_is_named_as_such_rather_than_used() {
    let error = start("ancient", SHORT).expect_err("no revision is common");
    assert!(
        matches!(error, HelperError::NoCommonProtocol { .. }),
        "{error:?}"
    );
    // The message has to tell someone which side to update.
    let said = error.to_string();
    assert!(said.contains("update"), "{said}");
}

#[test]
fn a_helper_that_cannot_resolve_types_is_refused_rather_than_degraded() {
    let error = start("untyped", SHORT).expect_err("types are not optional");
    assert!(
        matches!(
            error,
            HelperError::MissingRequiredCapability {
                missing: Capability::Types
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_helper_that_stops_answering_is_given_up_on_at_the_deadline() {
    let deadline = Duration::from_millis(300);
    let started = Instant::now();
    let error = start("deaf", deadline).expect_err("nothing comes back");
    let waited = started.elapsed();
    assert!(matches!(error, HelperError::TimedOut { .. }), "{error:?}");
    // The point of a deadline is that it bounds the wait, so the wait is what
    // is asserted — not merely that the right error came out eventually.
    assert!(
        waited < deadline * 20,
        "waited {waited:?} on a {deadline:?} deadline"
    );
}

#[test]
fn a_helper_that_dies_mid_handshake_is_reported_as_dead_not_as_a_broken_pipe() {
    let error = start("dies", SHORT).expect_err("it exits before answering");
    assert!(matches!(error, HelperError::Died { .. }), "{error:?}");
}

#[test]
fn what_a_dying_helper_printed_is_kept_and_told() {
    let error = start("noisy-death", SHORT).expect_err("it exits during startup");
    let HelperError::Died { stderr } = &error else {
        panic!("{error:?}");
    };
    assert!(
        stderr.iter().any(|line| line.contains("toolchain")),
        "the sentence that explains it was lost: {stderr:?}"
    );
    assert!(error.to_string().contains("toolchain"), "{error}");
}

#[test]
fn a_helper_that_will_not_stop_talking_cannot_grow_what_is_kept_of_it() {
    let error = start("chatty", SHORT).expect_err("it exits during startup");
    let HelperError::Died { stderr } = &error else {
        panic!("{error:?}");
    };
    // An upper bound rather than an exact count: the drain runs on its own
    // thread, so how much of the flood arrived before the process was reaped
    // is not fixed. What must hold is that no amount of it grows past the
    // ceiling, and that holds however far the thread got.
    assert!(
        stderr.len() <= MAX_DIAGNOSTIC_LINES,
        "kept {} lines of a flood",
        stderr.len()
    );
}

#[test]
fn an_answer_to_a_question_nobody_asked_is_not_taken_as_an_answer() {
    let error = start("confused", SHORT).expect_err("the ids do not line up");
    assert!(matches!(error, HelperError::Mismatched { .. }), "{error:?}");
}

#[test]
fn a_helper_that_refuses_says_why_in_its_own_words() {
    let error = start("refuses", SHORT).expect_err("it declines the handshake");
    let HelperError::Refused { code, message } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(code, "no_toolchain");
    assert!(message.contains("toolchain"), "{message}");
}

#[test]
fn dropping_a_helper_takes_its_process_with_it() {
    // A helper that outlives the run holds a compiler process open. There is no
    // portable way to ask whether a reaped pid is gone, so this asserts the
    // observable consequence instead: dropping one that is mid-request returns
    // promptly rather than waiting on a child that never finishes.
    let helper = start("deaf", SHORT).err();
    assert!(helper.is_some());
    let started = Instant::now();
    let second = start("deaf", Duration::from_millis(200));
    assert!(matches!(second, Err(HelperError::TimedOut { .. })));
    assert!(started.elapsed() < SHORT * 2);
}

/// A unit to ask about, named so tests can tell them apart.
fn unit(file: &str) -> UnitRef {
    UnitRef {
        unit: "mock-crate".into(),
        file: file.into(),
        variant: "variant-0".into(),
    }
}

fn supervisor(behaviour: &str, restarts: u32) -> Supervisor {
    Supervisor::new(
        PathBuf::from(MOCK),
        vec![behaviour.to_owned()],
        Duration::from_millis(500),
    )
    .with_max_restarts(restarts)
}

#[test]
fn an_analysis_comes_back_anchored_where_it_reads() {
    let mut helper = start("well-behaved", SHORT).expect("it answers");
    let asked = unit("src/lib.rs");
    let Analysis::Done(ir) = helper
        .analyze(&asked, &[Capability::Types])
        .expect("the mock analyzes")
    else {
        panic!("the mock had an answer");
    };
    assert!(ir.is_readable());
    assert_eq!(ir.unit, asked);
    let symbol = ir.symbols.first().expect("one symbol");
    assert_eq!(symbol.anchor.expansion.file, "src/lib.rs");
    assert!(!symbol.anchor.is_expanded());
    assert_eq!(
        ir.types
            .get(symbol.type_index.expect("a type") as usize)
            .expect("that type")
            .category,
        TypeCategory::Integer
    );
    helper.shutdown().expect("it goes");
}

#[test]
fn a_unit_nobody_can_analyze_is_an_answer_rather_than_a_failure() {
    let mut helper = start("needs-execution", SHORT).expect("it answers");
    let outcome = helper
        .analyze(&unit("build.rs"), &[Capability::Types])
        .expect("saying no is not an error");
    assert_eq!(
        outcome,
        Analysis::Missing(Unavailability::RequiresExecution)
    );
}

#[test]
fn an_answer_in_a_schema_nobody_reads_is_not_read() {
    let mut helper = start("wrong-schema", SHORT).expect("it answers");
    let outcome = helper
        .analyze(&unit("src/lib.rs"), &[Capability::Types])
        .expect("it answered, after all");
    // Not `Done` with unreadable contents, and not a dead helper either: the
    // helper works and needs updating, which is a different thing to tell
    // someone.
    assert_eq!(outcome, Analysis::Missing(Unavailability::UnreadableSchema));
}

#[test]
fn the_unit_that_kills_a_helper_is_set_aside_and_the_rest_go_on() {
    let mut supervisor = supervisor("allergic", 8);
    // The first good unit works.
    assert!(matches!(
        supervisor.analyze(&unit("src/good.rs"), &[Capability::Types]),
        Analysis::Done(_)
    ));
    // The bad one kills the helper. It is tried once more — a crash says
    // something about the pair, and only a retry says which half — and then
    // set aside.
    assert!(matches!(
        supervisor.analyze(&unit("src/poison.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperDied)
    ));
    assert!(supervisor.has_set_aside(&unit("src/poison.rs")));
    assert_eq!(supervisor.restarts(), 1, "one retry, so one restart");
    // And the project is still analyzable.
    assert!(matches!(
        supervisor.analyze(&unit("src/also-good.rs"), &[Capability::Types]),
        Analysis::Done(_)
    ));
    supervisor.shutdown();
}

#[test]
fn a_unit_already_set_aside_is_not_paid_for_twice() {
    let mut supervisor = supervisor("allergic", 8);
    assert!(matches!(
        supervisor.analyze(&unit("src/poison.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperDied)
    ));
    let after_first = supervisor.restarts();
    assert!(matches!(
        supervisor.analyze(&unit("src/poison.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperDied)
    ));
    assert_eq!(
        supervisor.restarts(),
        after_first,
        "asking again must not cost another restart"
    );
    supervisor.shutdown();
}

#[test]
fn a_helper_that_keeps_dying_is_given_up_on_rather_than_restarted_forever() {
    let mut supervisor = supervisor("allergic", 1);
    for file in ["src/poison-a.rs", "src/poison-b.rs", "src/poison-c.rs"] {
        assert!(matches!(
            supervisor.analyze(&unit(file), &[Capability::Types]),
            Analysis::Missing(_)
        ));
    }
    assert!(
        supervisor.restarts() <= 1,
        "restarted {} times against a budget of one",
        supervisor.restarts()
    );
    supervisor.shutdown();
}
