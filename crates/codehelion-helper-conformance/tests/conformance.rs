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
use codehelion_helper::protocol::{Capability, Execution, FrameError, PROTOCOL_VERSION};

/// The deadline for tests that are not about a deadline.
///
/// Generous on purpose. These tests wait for a mock to answer or to die, and
/// both happen at once when the machine is idle — the deadline is only reached
/// if something has genuinely hung, so a large one costs nothing and a tight
/// one turns a loaded machine into a failure. That the wait *is* bounded is
/// asserted where it belongs, by the test that gives a deaf helper its own
/// short deadline and measures how long it took to give up.
const DEADLINE: Duration = Duration::from_secs(20);

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
    let helper = start("well-behaved", DEADLINE).expect("the mock answers the handshake");
    assert_eq!(helper.identity().name, "codehelion-mock-helper");
    assert_eq!(helper.protocol_version(), PROTOCOL_VERSION);
    assert!(helper.offers(Capability::Types));
    assert!(!helper.offers(Capability::MirCfg));
    helper.shutdown().expect("it goes when asked");
}

/// A difference in revisions is a thing both sides must be able to discover,
/// so the handshake is answered whatever revision it arrives in and whatever
/// revision the answer comes back in. Refusing the answering frame for its
/// revision would report the difference as a peer that changed language
/// mid-conversation, and would never name either revision.
#[test]
fn a_helper_from_another_era_is_named_as_such_rather_than_used() {
    let error = start("ancient", DEADLINE).expect_err("the v1 protocol must match exactly");
    let HelperError::NoCommonProtocol { helper, required } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(*required, PROTOCOL_VERSION);
    assert_ne!(
        *helper, PROTOCOL_VERSION,
        "a helper from another era must be reported under its own revision"
    );
    // The message has to identify the exact protocol contract this build uses.
    let said = error.to_string();
    assert!(
        said.contains(&format!("requires protocol {PROTOCOL_VERSION}")),
        "{said}"
    );
}

/// And the mock has to be the peer it stands in for: a helper stamps its own
/// build's revision on every frame, including the handshake it answers. One
/// that echoed the caller's would agree with everybody and leave the path
/// above untested.
#[test]
fn a_mock_from_another_era_stamps_its_own_revision_the_way_a_helper_does() {
    let (frame, identity) = handshake_with(
        "ancient",
        // Asked in a revision neither side speaks, so an echo is visible as
        // one: nothing else would answer in this number.
        PROTOCOL_VERSION.saturating_add(7),
    );
    assert_ne!(frame, PROTOCOL_VERSION.saturating_add(7), "the mock echoed");
    assert_ne!(frame, PROTOCOL_VERSION);
    assert_eq!(
        frame, identity,
        "the frame and the identity must name one revision"
    );

    let (frame, identity) = handshake_with("well-behaved", PROTOCOL_VERSION.saturating_add(7));
    assert_eq!(frame, PROTOCOL_VERSION);
    assert_eq!(identity, PROTOCOL_VERSION);
}

/// Shake hands with the mock at `revision`, returning the revision its
/// answering frame carries and the one its identity announces.
#[allow(clippy::disallowed_types)]
fn handshake_with(behaviour: &str, revision: u32) -> (u32, u32) {
    use codehelion_helper::protocol::{
        ClientIdentity, Request, RequestBody, Response, ResponseBody, read_frame, write_frame,
    };
    use std::process::{Command, Stdio};

    // The conversation under test is a process boundary, so this test drives
    // one directly rather than through the client that is the thing being
    // stood in for.
    let mut child = Command::new(MOCK)
        .arg(behaviour)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the mock helper");
    let mut stdin = child.stdin.take().expect("the mock reads requests");
    write_frame(
        &mut stdin,
        &Request {
            protocol_version: revision,
            id: 0,
            body: RequestBody::Handshake(ClientIdentity {
                client: "conformance".into(),
                client_version: "0.0.0".into(),
                protocol: revision,
            }),
        },
    )
    .expect("send a handshake");
    let mut stdout = child.stdout.take().expect("the mock writes responses");
    let response: Response = read_frame(&mut stdout)
        .expect("read the answering frame")
        .expect("the mock answers a handshake");
    drop(stdin);
    let _ = child.wait();
    let ResponseBody::Handshake(identity) = response.body else {
        panic!("a handshake is answered with an identity");
    };
    (response.protocol_version, identity.protocol)
}

#[test]
fn a_helper_says_what_the_tree_it_was_pointed_at_is_read_under() {
    let mut helper = start("well-behaved", DEADLINE).expect("the mock answers");
    let described = helper.describe(Path::new("/repo")).expect("it describes");
    assert_eq!(described.features, vec!["mock/std".to_string()]);
    assert_eq!(described.cfgs, vec!["target_os = \"mock\"".to_string()]);
    helper.shutdown().expect("it goes when asked");
}

/// A helper that cannot establish what a tree is read under says so, and that
/// is not an empty description: a run that recorded its answers under
/// conditions nobody could name would compare them against answers from
/// conditions that were not those.
#[test]
fn conditions_nobody_could_establish_are_refused_rather_than_left_empty() {
    let mut helper = start("undescribed", DEADLINE).expect("the mock answers");
    let error = helper
        .describe(Path::new("/repo"))
        .expect_err("it cannot say");
    let HelperError::Refused { code, .. } = &error else {
        panic!("{error:?}");
    };
    assert_eq!(code, "no_build_description");
    helper.shutdown().expect("it goes when asked");
}

/// A helper says at the handshake what it would run if it were let to, so a
/// permission that would change nothing can be turned down before it is given.
/// Sent and ignored, the thin answer that follows reads as the project's.
#[test]
fn a_helper_says_what_it_would_run_before_anything_is_permitted() {
    let helper = start("well-behaved", DEADLINE).expect("the mock answers");
    assert!(helper.executes(Execution::BuildScript));
    assert!(!helper.executes(Execution::Configure));
    helper.shutdown().expect("it goes when asked");

    let inert = start("inert", DEADLINE).expect("the mock answers");
    assert!(!inert.executes(Execution::BuildScript));
    inert.shutdown().expect("it goes when asked");
}

#[test]
fn a_helper_that_cannot_resolve_types_is_refused_rather_than_degraded() {
    let error = start("untyped", DEADLINE).expect_err("types are not optional");
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
fn a_helper_that_cannot_resolve_names_is_refused_rather_than_degraded() {
    let error = start("unnamed", DEADLINE).expect_err("name resolution is not optional");
    assert!(
        matches!(
            error,
            HelperError::MissingRequiredCapability {
                missing: Capability::NameResolution
            }
        ),
        "{error:?}"
    );
}

#[test]
fn a_busy_helper_shutdown_does_not_spend_another_analysis_timeout() {
    let analysis_timeout = Duration::from_secs(2);
    let mut helper = start("deaf-after-setup", analysis_timeout).expect("it shakes hands");
    let analysis = helper
        .analyze(&unit("src/hung.rs"), &[Capability::Types])
        .expect_err("the analysis does not answer");
    assert!(
        matches!(analysis, HelperError::TimedOut { .. }),
        "{analysis:?}"
    );
    assert!(helper.is_poisoned_after_timeout());
    let next = helper
        .analyze(&unit("src/after-timeout.rs"), &[Capability::Types])
        .expect_err("a delayed response cannot be paired with a new request");
    assert!(
        matches!(next, HelperError::PoisonedAfterTimeout),
        "{next:?}"
    );

    let started = Instant::now();
    helper.shutdown().expect("the hung child is killed");
    assert!(
        started.elapsed() < analysis_timeout / 2,
        "shutdown waited {:?} after an analysis timeout of {analysis_timeout:?}",
        started.elapsed()
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
    let error = start("dies", DEADLINE).expect_err("it exits before answering");
    assert!(matches!(error, HelperError::Died { .. }), "{error:?}");
}

#[test]
fn stdout_diagnostics_are_refused_as_a_corrupt_protocol_frame() {
    let error = start("noisy-stdout", DEADLINE).expect_err("stdout is the protocol only");
    assert!(
        matches!(error, HelperError::Frame(FrameError::TooLarge { .. })),
        "{error:?}"
    );
}

#[test]
fn an_oversized_protocol_frame_is_refused_before_it_is_allocated() {
    let error = start("oversized-frame", DEADLINE).expect_err("frame exceeds the ceiling");
    assert!(
        matches!(error, HelperError::Frame(FrameError::TooLarge { .. })),
        "{error:?}"
    );
}

#[test]
fn what_a_dying_helper_printed_is_kept_and_told() {
    let error = start("noisy-death", DEADLINE).expect_err("it exits during startup");
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
    let error = start("chatty", DEADLINE).expect_err("it exits during startup");
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
    let error = start("confused", DEADLINE).expect_err("the ids do not line up");
    assert!(matches!(error, HelperError::Mismatched { .. }), "{error:?}");
}

/// A matching request id is not enough: after negotiation, every response
/// must use the revision the conversation settled on.
#[test]
fn a_response_that_changes_protocol_revision_is_rejected() {
    let mut helper = start("wrong-revision-after-setup", DEADLINE)
        .expect("the mock establishes a normal handshake");
    let error = helper
        .analyze(&unit("src/lib.rs"), &[Capability::Types])
        .expect_err("the response changes revision after setup");
    assert!(
        matches!(error, HelperError::ProtocolMismatch { .. }),
        "{error:?}"
    );
}

#[test]
fn a_helper_that_refuses_says_why_in_its_own_words() {
    let error = start("refuses", DEADLINE).expect_err("it declines the handshake");
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
    let deadline = Duration::from_millis(200);
    let helper = start("deaf", deadline).err();
    assert!(helper.is_some());
    let started = Instant::now();
    let second = start("deaf", deadline);
    assert!(matches!(second, Err(HelperError::TimedOut { .. })));
    // Bounded by this test's own deadline rather than the suite's: what is
    // being asserted is that the drop did not wait on the first child, and a
    // bound read off an unrelated constant would stop saying so if that
    // constant moved.
    assert!(started.elapsed() < deadline * 30, "{:?}", started.elapsed());
}

/// A unit to ask about, named so tests can tell them apart.
fn unit(file: &str) -> UnitRef {
    UnitRef {
        unit: "mock-crate".into(),
        file: file.into(),
        variant: "variant-0".into(),
    }
}

/// A supervisor on the same deadline as every other test here.
///
/// None of these tests is about a helper being slow — they are about one that
/// dies — and the deadline covers starting the process as well as answering.
/// A budget tight enough to be quick would make a loaded machine look like a
/// helper that would not start, which is the failure these tests exist to tell
/// apart from the one they are about.
fn supervisor(behaviour: &str, restarts: u32) -> Supervisor {
    Supervisor::new(PathBuf::from(MOCK), vec![behaviour.to_owned()], DEADLINE)
        .with_max_restarts(restarts)
}

#[test]
fn an_analysis_comes_back_anchored_where_it_reads() {
    let mut helper = start("well-behaved", DEADLINE).expect("it answers");
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
    let mut helper = start("needs-execution", DEADLINE).expect("it answers");
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
    let mut helper = start("wrong-schema", DEADLINE).expect("it answers");
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
    assert_eq!(
        supervisor.take_diagnostics(),
        vec!["mock compiler crashed while reading src/poison.rs"],
        "the diagnostic follows the unavailable unit after its helper has exited"
    );
    assert_eq!(supervisor.restarts(), 1, "one retry, so one restart");
    // And the project is still analyzable.
    assert!(matches!(
        supervisor.analyze(&unit("src/also-good.rs"), &[Capability::Types]),
        Analysis::Done(_)
    ));
    supervisor.shutdown();
}

/// A run records which helper answered it, and it records that after the
/// helper is gone. Nothing is claimed before one has spoken, and what it said
/// outlives it.
#[test]
fn who_answered_is_still_known_once_the_helper_has_gone() {
    let mut supervisor = supervisor("well-behaved", 0);
    assert!(
        supervisor.spoke_with().is_none(),
        "nothing has been started, so nobody has said anything"
    );
    assert!(matches!(
        supervisor.analyze(&unit("src/lib.rs"), &[Capability::Types]),
        Analysis::Done(_)
    ));
    supervisor.shutdown();
    let identity = supervisor.spoke_with().expect("one helper answered");
    assert_eq!(identity.name, "codehelion-mock-helper");
    assert_eq!(identity.protocol, PROTOCOL_VERSION);
    assert!(identity.capabilities.contains(&Capability::Types));
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

/// What stopped a run is what every unit after it is reported under. Falling
/// back to a generic dead helper would bury the one condition that explains
/// the whole scan under one symptom of it, repeated once per file.
#[test]
fn units_after_a_run_stops_asking_are_reported_under_what_stopped_it() {
    let mut supervisor = supervisor("allergic", 1);
    // The first unit exhausts the budget: it kills the helper, is retried
    // once, and kills the restarted one too.
    assert_eq!(
        supervisor.analyze(&unit("src/poison-a.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperDied)
    );
    assert!(
        !supervisor.take_diagnostics().is_empty(),
        "the crash was reported without the sentence that explains it"
    );
    for file in ["src/poison-b.rs", "src/second.rs"] {
        assert_eq!(
            supervisor.analyze(&unit(file), &[Capability::Types]),
            Analysis::Missing(Unavailability::RestartBudgetExhausted),
            "{file} was reported under a symptom rather than under the budget"
        );
    }
    supervisor.shutdown();
}

/// The same for a helper that never started: every unit says the helper cannot
/// be spoken to, not that it died answering them.
#[test]
fn every_unit_of_an_unusable_helper_names_why_it_is_unusable() {
    let mut supervisor = supervisor("ancient", 3);
    for file in ["src/first.rs", "src/second.rs", "src/third.rs"] {
        assert_eq!(
            supervisor.analyze(&unit(file), &[Capability::Types]),
            Analysis::Missing(Unavailability::ToolchainMismatch),
            "{file} lost the reason the helper could not be used"
        );
        let said = supervisor.take_diagnostics();
        assert!(
            said.iter().any(|line| line.contains("protocol")),
            "{file} was reported without what the revisions were: {said:?}"
        );
    }
    assert_eq!(
        supervisor.restarts(),
        0,
        "a helper that will not start is not started again per unit"
    );
    supervisor.shutdown();
}

/// A unit set aside after two attempts keeps the condition it met, so a unit
/// that timed out twice is not later reported as one that killed a helper.
#[test]
fn a_unit_set_aside_keeps_the_condition_it_actually_met() {
    let mut supervisor = Supervisor::new(
        PathBuf::from(MOCK),
        vec!["deaf-on-poison".to_owned()],
        Duration::from_millis(300),
    )
    .with_max_restarts(8);
    assert_eq!(
        supervisor.analyze(&unit("src/poison.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperTimedOut)
    );
    assert!(supervisor.has_set_aside(&unit("src/poison.rs")));
    assert_eq!(
        supervisor.analyze(&unit("src/poison.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperTimedOut),
        "asking again reported a condition this unit never met"
    );
    supervisor.shutdown();
}

/// A helper that answers a unit with a refusal has received the request and
/// declined it. Restarting puts the same question to the same program, so it
/// spends a restart to be told the same thing and takes the budget away from
/// the crashes a restart does help with.
#[test]
fn a_refused_unit_does_not_cost_a_restart_and_the_rest_go_on() {
    let mut supervisor = supervisor("declines-analysis", 3);
    assert_eq!(
        supervisor.analyze(&unit("src/first.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::NotSupported)
    );
    let said = supervisor.take_diagnostics();
    assert!(
        said.iter().any(|line| line.contains("unreadable_request")),
        "the refusal reached the caller without its own words: {said:?}"
    );
    assert_eq!(
        supervisor.analyze(&unit("src/second.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::NotSupported)
    );
    assert_eq!(
        supervisor.restarts(),
        0,
        "a refusal was treated as a crash and spent the restart budget"
    );
    assert!(
        !supervisor.has_set_aside(&unit("src/first.rs")),
        "a unit the helper survived was set aside"
    );
    supervisor.shutdown();
}

/// A reason is a name a report can count; the sentence beside it is the whole
/// difference between a scan somebody can act on and a tally of unavailability.
/// Both a helper that declines a unit and one that never answers have one.
#[test]
fn a_refused_unit_and_a_timed_out_unit_both_arrive_with_a_sentence() {
    let mut supervisor = supervisor("unbuildable", 3);
    assert_eq!(
        supervisor.analyze(&unit("src/uncovered.cc"), &[Capability::Types]),
        Analysis::Missing(Unavailability::NoBuildInformation)
    );
    let said = supervisor.take_diagnostics();
    assert!(
        said.iter()
            .any(|line| line.contains("no compilation command covers src/uncovered.cc")),
        "what the helper said about the refusal was dropped: {said:?}"
    );
    supervisor.shutdown();

    let mut supervisor = Supervisor::new(
        PathBuf::from(MOCK),
        vec!["noisy-deafness".to_owned()],
        Duration::from_millis(300),
    )
    .with_max_restarts(1);
    assert_eq!(
        supervisor.analyze(&unit("src/slow.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::HelperTimedOut)
    );
    let said = supervisor.take_diagnostics();
    assert!(
        said.iter().any(|line| line.contains("expanding macros")),
        "a timeout lost what the helper printed before it stopped: {said:?}"
    );
    supervisor.shutdown();
}

/// A helper that answered one unit and refused the next must not have the
/// first unit's silence read as the second's explanation, or the other way
/// round.
#[test]
fn what_was_said_about_one_unit_is_not_reported_against_another() {
    let mut supervisor = supervisor("unbuildable", 3);
    assert!(matches!(
        supervisor.analyze(&unit("src/first.cc"), &[Capability::Types]),
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
    assert!(
        supervisor
            .take_diagnostics()
            .iter()
            .any(|line| line.contains("src/first.cc"))
    );
    assert!(matches!(
        supervisor.analyze(&unit("src/second.cc"), &[Capability::Types]),
        Analysis::Missing(Unavailability::NoBuildInformation)
    ));
    let said = supervisor.take_diagnostics();
    assert!(
        said.iter().any(|line| line.contains("src/second.cc")),
        "{said:?}"
    );
    assert!(
        !said.iter().any(|line| line.contains("src/first.cc")),
        "one unit's explanation was reported against the next: {said:?}"
    );
    supervisor.shutdown();
}

/// An answer too large for one frame is this unit's unavailability, and the
/// helper goes on answering about the rest of the project.
#[test]
fn an_answer_that_will_not_fit_in_a_frame_is_the_units_unavailability() {
    let mut supervisor = supervisor("oversized-answer", 3);
    assert_eq!(
        supervisor.analyze(&unit("src/enormous.rs"), &[Capability::Types]),
        Analysis::Missing(Unavailability::ResponseTooLarge)
    );
    assert_eq!(
        supervisor.restarts(),
        0,
        "an oversized answer was treated as a crash"
    );
    supervisor.shutdown();
}

/// A read boundary is sent with the request and enforced by the helper, so a
/// unit resolving outside it comes back as an answer about that unit rather
/// than as a broken conversation.
#[test]
fn a_unit_outside_the_declared_read_boundary_is_refused_by_the_helper() {
    let mut supervisor = supervisor("bounded", 3);
    let boundary = Path::new("/repo");
    assert!(matches!(
        supervisor.analyze_with_command_and_boundary(
            &unit("/repo/src/inside.rs"),
            None,
            Some(boundary),
            &[Capability::Types],
        ),
        Analysis::Done(_)
    ));
    assert_eq!(
        supervisor.analyze_with_command_and_boundary(
            &unit("/elsewhere/outside.rs"),
            None,
            Some(boundary),
            &[Capability::Types],
        ),
        Analysis::Missing(Unavailability::NotSupported)
    );
    let said = supervisor.take_diagnostics();
    assert!(
        said.iter()
            .any(|line| line.contains("outside the declared read boundary")),
        "{said:?}"
    );
    supervisor.shutdown();
}

/// Whether a reason is worth another attempt decides where the restart budget
/// goes, so every reason answers that question here. The match is exhaustive:
/// a reason added without a decision stops this compiling.
#[test]
fn every_reason_a_unit_has_no_ir_says_whether_a_retry_could_change_it() {
    for reason in Unavailability::ALL {
        let worth_retrying = match reason {
            // A helper that stopped may have stopped on this input, and only
            // asking again says which of the two it was about.
            Unavailability::HelperDied | Unavailability::HelperTimedOut => true,
            // Everything the helper decided, and everything about the pair of
            // programs, is the same on the next attempt.
            Unavailability::RequiresExecution
            | Unavailability::MetadataUnavailable
            | Unavailability::NoBuildInformation
            | Unavailability::ToolchainMismatch
            | Unavailability::UnreadableSchema
            | Unavailability::ResponseTooLarge
            | Unavailability::RestartBudgetExhausted
            | Unavailability::NotSupported => false,
        };
        assert_eq!(
            reason.worth_retrying(),
            worth_retrying,
            "{} is classified against what a retry can change",
            reason.name()
        );
    }
}
