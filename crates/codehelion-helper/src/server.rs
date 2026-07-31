//! The half of the boundary a helper implements.
//!
//! [`client`](crate::client) runs a helper; this is what a helper runs. A
//! backend says who it is and answers one unit at a time, and everything about
//! being a process — reading frames, matching answers to questions, ending
//! cleanly — is handled here, once, for every helper written in Rust.
//!
//! The loop, not the backend, decides which request an answer belongs to. A
//! backend that could choose its own correlation id would be able to produce
//! something indistinguishable, from the client's side, from a helper that lost
//! a message, and no backend has any reason to want that. For the same reason
//! [`Answer::Unavailable`] carries only a reason: the unit it is about is the
//! one that was asked for.
//!
//! The conformance mock does not use this loop, and should not: its purpose is
//! to break the rules this enforces.

use std::io::{Read, Write};

use crate::ir::{CompilerIr, Unavailability};
use crate::protocol::{
    Analyze, BuildDescription, DescribeBuild, Failure, FrameError, HelperIdentity,
    PROTOCOL_VERSION, Request, RequestBody, Response, ResponseBody, write_frame,
};

/// What a backend can say about one unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// What the compiler knows.
    Analyzed(Box<CompilerIr>),
    /// Nothing can be known about this unit, and why.
    ///
    /// A working helper meeting a unit it cannot analyse — not a failure. Every
    /// real project has some.
    Unavailable(Unavailability),
    /// The request itself could not be handled.
    Failed(Failure),
}

/// What a backend can say about the conditions a tree is read under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Description {
    /// What the code is analysed under. Empty when there is no project here to
    /// describe, which is a description rather than a failure to make one.
    Build(BuildDescription),
    /// The conditions could not be established.
    ///
    /// Apart from an empty description on purpose: a run cannot record its
    /// answers under conditions nobody could name, so this stops the run
    /// instead of filing it under conditions that were guessed at.
    Failed(Failure),
}

/// One compiler, behind one program.
pub trait Backend {
    /// Who this helper is and what it can supply.
    ///
    /// Asked once per connection, at the handshake. What it claims here bounds
    /// what it will be asked for, so a capability listed is a promise.
    fn identity(&self) -> HelperIdentity;

    /// What the code in a tree is analysed under.
    fn describe(&mut self, request: &DescribeBuild) -> Description;

    /// Analyse one unit.
    fn analyze(&mut self, request: &Analyze) -> Answer;
}

/// Serve requests until the stream ends or a shutdown is asked for.
///
/// # Errors
///
/// Fails if a frame cannot be read or written. A malformed request ends the
/// loop rather than being skipped: the stream's framing is no longer
/// trustworthy once a frame has not parsed, so continuing would mean guessing
/// where the next message starts.
pub fn serve<B: Backend, R: Read, W: Write>(
    backend: &mut B,
    input: &mut R,
    output: &mut W,
) -> Result<(), FrameError> {
    loop {
        let Some(request): Option<Request> = crate::protocol::read_frame(input)? else {
            return Ok(());
        };
        let closing = matches!(request.body, RequestBody::Shutdown);
        let body = answer(backend, &request);
        write_frame(
            output,
            &Response {
                // The revision this build writes, not the one that was read: a
                // peer that asked in a revision this build does not speak is
                // told so rather than answered in a language nobody chose.
                protocol_version: PROTOCOL_VERSION,
                id: request.id,
                body,
            },
        )?;
        if closing {
            return Ok(());
        }
    }
}

fn answer<B: Backend>(backend: &mut B, request: &Request) -> ResponseBody {
    // Answered before the revision is checked, and it is the only message that
    // is: a handshake is how two peers find out what they can say to each
    // other, so refusing it for arriving in the wrong revision would make the
    // question unaskable by anyone who did not already know the answer.
    if let RequestBody::Handshake(_) = &request.body {
        return ResponseBody::Handshake(Box::new(backend.identity()));
    }
    if request.protocol_version != PROTOCOL_VERSION {
        return ResponseBody::Failed(Failure {
            code: "protocol_version".to_string(),
            message: format!(
                "this helper speaks protocol {PROTOCOL_VERSION}, and the request arrived in {}",
                request.protocol_version
            ),
        });
    }
    match &request.body {
        // Answered above, before anything was agreed.
        RequestBody::Handshake(_) => ResponseBody::Handshake(Box::new(backend.identity())),
        RequestBody::DescribeBuild(describe) => match backend.describe(describe) {
            Description::Build(build) => ResponseBody::Build(Box::new(build)),
            Description::Failed(failure) => ResponseBody::Failed(failure),
        },
        RequestBody::Analyze(analyze) => match backend.analyze(analyze) {
            Answer::Analyzed(ir) => ResponseBody::Analyzed(ir),
            Answer::Unavailable(reason) => ResponseBody::Unavailable {
                unit: analyze.unit.clone(),
                reason,
            },
            Answer::Failed(failure) => ResponseBody::Failed(failure),
        },
        RequestBody::Shutdown => ResponseBody::Shutdown,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ir::UnitRef;
    use crate::protocol::{Capability, ClientIdentity, read_frame};

    struct Fixed {
        answer: Answer,
        asked: Vec<UnitRef>,
    }

    impl Backend for Fixed {
        fn identity(&self) -> HelperIdentity {
            HelperIdentity {
                name: "fixed".to_string(),
                version: "0.1.0".to_string(),
                protocol: PROTOCOL_VERSION,
                toolchains: vec!["fixed 1.0".to_string()],
                capabilities: vec![Capability::Types],
                executes: Vec::new(),
            }
        }

        fn describe(&mut self, _request: &DescribeBuild) -> Description {
            Description::Build(BuildDescription {
                features: vec!["ledger/std".to_string()],
                cfgs: vec!["unix".to_string()],
            })
        }

        fn analyze(&mut self, request: &Analyze) -> Answer {
            self.asked.push(request.unit.clone());
            self.answer.clone()
        }
    }

    fn unit() -> UnitRef {
        UnitRef {
            unit: "ledger".to_string(),
            file: "src/lib.rs".to_string(),
            variant: "host".to_string(),
        }
    }

    fn conversation(requests: &[RequestBody]) -> (Vec<Response>, Fixed) {
        let mut input = Vec::new();
        for (index, body) in requests.iter().enumerate() {
            write_frame(
                &mut input,
                &Request {
                    protocol_version: PROTOCOL_VERSION,
                    id: index as u64,
                    body: body.clone(),
                },
            )
            .unwrap();
        }
        let mut backend = Fixed {
            answer: Answer::Unavailable(Unavailability::RequiresExecution),
            asked: Vec::new(),
        };
        let mut output = Vec::new();
        serve(&mut backend, &mut input.as_slice(), &mut output).unwrap();
        let mut stream = output.as_slice();
        let mut responses = Vec::new();
        while let Some(response) = read_frame::<_, Response>(&mut stream).unwrap() {
            responses.push(response);
        }
        (responses, backend)
    }

    fn handshake() -> RequestBody {
        RequestBody::Handshake(ClientIdentity {
            client: "test".to_string(),
            client_version: "0.1.0".to_string(),
            protocol: PROTOCOL_VERSION,
        })
    }

    #[test]
    fn a_handshake_is_answered_with_what_the_backend_says_it_is() {
        let (responses, _) = conversation(&[handshake()]);
        assert_eq!(responses.len(), 1);
        match &responses[0].body {
            ResponseBody::Handshake(identity) => {
                assert_eq!(identity.name, "fixed");
                assert_eq!(identity.capabilities, vec![Capability::Types]);
            }
            other => panic!("{other:?}"),
        }
    }

    /// The loop, not the backend, decides which question an answer belongs to.
    #[test]
    fn every_answer_carries_the_id_of_the_question_it_answers() {
        let (responses, _) = conversation(&[
            handshake(),
            RequestBody::Analyze(Analyze {
                unit: unit(),
                compile_command: None,
                want: vec![Capability::Types],
                permitted: Vec::new(),
            }),
            RequestBody::Shutdown,
        ]);
        assert_eq!(
            responses.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
    }

    /// And which unit an unavailability is about, so a backend cannot report
    /// one unit's failure against another.
    #[test]
    fn an_unavailable_answer_is_about_the_unit_that_was_asked_for() {
        let (responses, backend) = conversation(&[RequestBody::Analyze(Analyze {
            unit: unit(),
            compile_command: None,
            want: vec![Capability::Types],
            permitted: Vec::new(),
        })]);
        assert_eq!(backend.asked, vec![unit()]);
        match &responses[0].body {
            ResponseBody::Unavailable {
                unit: answered,
                reason,
            } => {
                assert_eq!(*answered, unit());
                assert_eq!(*reason, Unavailability::RequiresExecution);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_shutdown_is_acknowledged_and_ends_the_conversation() {
        let (responses, _) = conversation(&[
            RequestBody::Shutdown,
            // Never read: the loop stops at the shutdown above.
            handshake(),
        ]);
        assert_eq!(responses.len(), 1);
        assert!(matches!(responses[0].body, ResponseBody::Shutdown));
    }

    #[test]
    fn a_description_says_what_the_backend_reads_the_tree_under() {
        let (responses, _) = conversation(&[RequestBody::DescribeBuild(DescribeBuild {
            root: "/repo".to_string(),
        })]);
        match &responses[0].body {
            ResponseBody::Build(build) => {
                assert_eq!(build.features, vec!["ledger/std".to_string()]);
                assert_eq!(build.cfgs, vec!["unix".to_string()]);
            }
            other => panic!("{other:?}"),
        }
    }

    /// A request in a revision this build does not speak is refused, rather
    /// than answered in a language neither side chose.
    #[test]
    fn a_request_from_another_revision_is_refused_by_name() {
        let response = at_revision(
            PROTOCOL_VERSION + 7,
            RequestBody::Analyze(Analyze {
                unit: unit(),
                compile_command: None,
                want: vec![Capability::Types],
                permitted: Vec::new(),
            }),
        );
        assert_eq!(response.id, 3);
        assert_eq!(response.protocol_version, PROTOCOL_VERSION);
        match &response.body {
            ResponseBody::Failed(failure) => assert_eq!(failure.code, "protocol_version"),
            other => panic!("{other:?}"),
        }
    }

    /// Except the handshake, which is how a revision gets agreed in the first
    /// place. Refusing it for arriving in the wrong one would leave a peer that
    /// guessed wrong with no way to find out what to guess instead.
    #[test]
    fn a_handshake_from_another_revision_is_answered_rather_than_refused() {
        let response = at_revision(PROTOCOL_VERSION + 7, handshake());
        match &response.body {
            ResponseBody::Handshake(identity) => assert_eq!(identity.name, "fixed"),
            other => panic!("{other:?}"),
        }
    }

    /// One request, sent in `revision` whatever this build speaks.
    fn at_revision(revision: u32, body: RequestBody) -> Response {
        let mut input = Vec::new();
        write_frame(
            &mut input,
            &Request {
                protocol_version: revision,
                id: 3,
                body,
            },
        )
        .unwrap();
        let mut backend = Fixed {
            answer: Answer::Unavailable(Unavailability::NotSupported),
            asked: Vec::new(),
        };
        let mut output = Vec::new();
        serve(&mut backend, &mut input.as_slice(), &mut output).unwrap();
        read_frame(&mut output.as_slice()).unwrap().unwrap()
    }

    /// Framing is no longer trustworthy once a frame has not parsed, so the
    /// loop stops rather than guessing where the next message begins.
    #[test]
    fn a_frame_that_does_not_parse_ends_the_loop_rather_than_being_skipped() {
        let mut input = Vec::new();
        write_frame(&mut input, &serde_json::json!({"not": "a request"})).unwrap();
        let mut backend = Fixed {
            answer: Answer::Unavailable(Unavailability::NotSupported),
            asked: Vec::new(),
        };
        let mut output = Vec::new();
        let error = serve(&mut backend, &mut input.as_slice(), &mut output).unwrap_err();
        assert!(matches!(error, FrameError::Malformed(_)), "{error:?}");
        assert!(output.is_empty());
    }
}
